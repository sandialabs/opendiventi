/*
 * Handles a single query session. Parses the query, constructs a response, and sends it back. 
 */

#include "diventi.h"
#include "Control.h"
#include "QuerySession.h"
#include "KeyValuePair.h"
#include "TokuHandler.h"

#include "IP_Key.h"
#include "Basic_Key.h"

#include <boost/beast/version.hpp>
#include <boost/thread/thread.hpp>
#include <climits>
#include <chrono>
#include <fstream>

using tcp = boost::asio::ip::tcp;
namespace http = boost::beast::http;

static Key *getFirstKey(std::map<std::string, std::string> &args) {
	if( keyCompare == IPv4_KeyCompare ) {
		return IP_Key::createFirstKey(args);
	}
	else if( keyCompare == BASIC_KeyCompare ) {
		return Basic_Key::createFirstKey(args);
	}
	else {
		diventi_error("ERROR: keyCompare doesn't match ipv4 or basic");                
        return IP_Key::createFirstKey(args);
	}
}

static Key *getLastKey(std::map<std::string, std::string> &args) {
	if( keyCompare == IPv4_KeyCompare ) {
		return IP_Key::createLastKey(args);
	}
	else if( keyCompare == BASIC_KeyCompare ) {
		return Basic_Key::createLastKey(args);
	}
	else {
		diventi_error("ERROR: keyCompare doesn't match ipv4 or basic");                
        return IP_Key::createLastKey(args);
	}
}

QuerySession::QuerySession(Control *_control, tcp::socket *_sock){
	control = _control;		//used for getting the sample file and the number of inserts
							//Additionally use controls tkhandler for getting the DBT
	sock = _sock;			//the socket used for: I/O object and inteacions with the user
	running = false;		//running 	 used for: Simple variable used by run()
}

QuerySession::~QuerySession(){
	delete sock;
}

void QuerySession::run(){ //if were not running then initialize by calling doRead()
	if (!running){
		running = true;
		doRead();
	}
}
//perform a read of the socket and grab a query from it
//called by: handleWrite() and run()
void QuerySession::doRead(){
	//Asynchronous read of a message from the user's input stream
	//supply async with the io_context, the buffer, and a call to boost::bind
	//this call the boost::bind is the handler function
		//Boost bind will create a function that returns handleRead(placeholders::error, placeholders::bytes_transferred)
		//our function handleRead
		//some boost::asio::placeholders which are used in combination with bind to represent arguments to the function
			//these arguments are of form unspecified error and unspecified bytes_transferred
	http::async_read(*sock, buff, req,
					boost::bind(&QuerySession::handleRead, this, 
					boost::asio::placeholders::error,
					boost::asio::placeholders::bytes_transferred));
}

//handleRead is used for taking in the query, validating it, and passing it on
//Called by doRead
void QuerySession::handleRead(boost::system::error_code ec, std::size_t bytes_transferred){
	boost::ignore_unused(bytes_transferred); //suppresses compiler warnings about unused arguments

	if (ec){ //if there's an error: print it out and if it was eof then stop
		debug(1, "Error: %s\n", ec.message().c_str());
		if (ec == boost::asio::error::eof){
			debug(20, "eof of read, deleting this\n");
			sock->shutdown(tcp::socket::shutdown_send, ec);
			delete this;
			return;
		}
	}

	// If not correct url or method, send back error code
	if(req.method() != http::verb::get){
		error(http::status::method_not_allowed, "Unsupported method " + std::string(to_string(req.method())));
	} else if (req.target().find("/query") == boost::beast::string_view::npos){
		error(http::status::not_found, "Requested URL not found");
	} else{
		resolveQuery(); //if everything looks good call resolveQuery
	}
}

//handleRead and handleWrite differ in that handlewrite deals with esuring the data was properly returned
//Called by: QuerySession::send
void QuerySession::handleWrite(boost::system::error_code ec, std::size_t bytes_transferred){
	boost::ignore_unused(bytes_transferred);

	res = nullptr;	// Done with this response

	if (ec){ //if there's an error code
		if (ec == boost::asio::error::eof){
			debug(0, "eof of write, deleting this\n");
			sock->shutdown(tcp::socket::shutdown_send, ec); //close the socket
			delete this;
			return;
		} else{
			debug(30, "Error: %s\n", ec.message().c_str()); //if there was an error (not eof) call debug
		}
	}
	// Old way was to be ready to receive another query
	// doRead();
	// New way is for every querySession to only do stuff for one query
	// Then it annihilates itself and a new instance is spun up for the next query
	debug(40, "reached end of query... deleting\n");
	sock->shutdown(tcp::socket::shutdown_send, ec);
	delete this;
}

//error messaging for things specific to queries. Sends the error to the user
//called by: handleRead if the query is of invalid format
void QuerySession::error(http::status s, std::string what){
	http::response<http::string_body> res{s, req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/html");
    res.keep_alive(req.keep_alive());
    res.body() = "An error occurred: " + what;
    res.prepare_payload();
    send(res);
}

//send the result of the query to the user.
//Check that it suceeded using handleWrite
//Called by: resolveQuery
void QuerySession::send(http::response<http::string_body>& msg){
 	// Keep a shared ptr so we don't accidentally delete this too early
 	res = std::make_shared<http::response<http::string_body>>(msg);
 	http::async_write(*sock, *res,
 					boost::bind(&QuerySession::handleWrite, this, 
					boost::asio::placeholders::error,
					boost::asio::placeholders::bytes_transferred));
 }

//Checks to ensure that the query actually has an ip address
bool QuerySession::validateQuery(std::map<std::string, std::string> &args){
	if (args.count("ip") == 0){
		error(http::status::bad_request, "Invalid query... \"ip\" argument required");
		return false;
	}
	if (args.count("range") != 0 && args["range"] != args["ip"] && (args.count("startTime") != 0 || args.count("endTime") != 0)) {
		error(http::status::bad_request, "Invalid query... \"range\" cannot be used with time constraints. Send multiple queries or use post query filtering if this functionality is necessary.");
		return false;
	}

	return true;
}

/*
	Where the actual work gets done
	Takes the query, calls other functions to assure that it's valid
	Constructs a query to Tokuhandler to get the data it wants
	Once it gets the data it formats it all nice like
	Then it sends the response to the user

	Error checking is extensive throughout
*/
void QuerySession::resolveQuery(){
	//the result of parsing the arguments in the query is stored in args
	std::map<std::string, std::string> args = parseURLArgs(std::string(req.target()));
	if (!validateQuery(args)){
		return;	// validate query sends response so can be specific about failure
	}
	std::chrono::time_point<std::chrono::system_clock> start = std::chrono::system_clock::now();

	// Construct query
	bool getStats;
	Key *startKey;
	Key *endKey;
	int _type;
	try{
		getStats = statistics(args);
		startKey = getFirstKey(args);
		debug(70, "starting key: %s", startKey->toExtendedString().c_str());
		endKey = getLastKey(args);
		debug(70, "end key: %s", endKey->toExtendedString().c_str());
		_type = type(args);
	} catch(std::invalid_argument &e){
		error(http::status::bad_request, "The server was unable to parse the arguments of your http request. Please try again.\n");
		debug(10, "Had error parsing arguments in http request\n");
		return;
	}
	// Query Tokuhandler
	std::vector <KeyValuePair> *answer; //answer is a ptr to a vector of KeyValuePairs
	try{
		answer = control->TKhandler->get(startKey, endKey); //supply tokuhandler with the startKey and endKey and ask for data that fits
	} catch(std::runtime_error &e){ //if Tokuhandler throws a error 
		error(http::status::internal_server_error, "The server experienced an internal error. Please try again.\n");
		debug(10,"Had error processing query\n");
		return;
	}
	
	uint64_t numReturned = answer->size();
	debug(30,"Found %ld results\n",numReturned);
	//format the response
	std::string body = formatRes(answer, _type);
	
	//If collecting statistics, append relevant information
	std::chrono::duration<double> diff = std::chrono::system_clock::now() - start;
	if(getStats) {
		body += "\nTime to get responses: " + std::to_string(diff.count()) + " Number returned: " + std::to_string(numReturned);
	}
	#ifdef BENCHMARK
		std::fstream *file = control->getSampleFile();
		(*file) << "QUERY:" << std::string(req.target()) << ":" << std::to_string(diff.count()) << ":" << std::to_string(numReturned) << std::endl;
	#endif

	// If browser request, maintain space formatting with html
	std::string agent = std::string(req[http::field::user_agent]);
	if (agent.find("Firefox") != std::string::npos ||
		agent.find("Chrome") != std::string::npos ||
		agent.find("Chromium") != std::string::npos ||
		agent.find("Safari") != std::string::npos ||
		agent.find("Edge") != std::string::npos){

		body = "<pre>" + body + "</pre>";
	}
	debug(60, "user agent: %s\n", agent.c_str());

	// Prepare and send response
	// uint32_t len = strlen(body.c_str());
	// while( len > MAX_BODY_SIZE ) {
	// 	//split the long body into small subsets
	// 	std::string bodyOut = body.substr(0, MAX_BODY_SIZE);
	// 	body = body.substr(MAX_BODY_SIZE, len);
	// 	len = strlen(body.c_str());
	// 	//send the substring
	// 	http::response<http::string_body> res{http::status::ok, req.version()};
	//     res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
	//     res.set(http::field::content_type, "text/html");
	//     res.keep_alive(req.keep_alive());
	//     res.body() = bodyOut;
	//     res.prepare_payload();
	//     send(res);
	// }
	//send either the full body if it was small than max size or the left over substring

	debug(150,"%s\n", body.c_str());
	http::response<http::string_body> res{http::status::ok, req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/html");
    res.keep_alive(req.keep_alive());
    res.body() = body;
    res.prepare_payload();
    send(res);
    delete startKey;
    delete endKey;
}

/*	
	Evan - 06/21
	Function to format the result of the query
*/
std::string QuerySession::formatRes(std::vector <KeyValuePair> *answer, int type) {
	//Goal is human readable thus nice formatting
	//if the user just wants the normal formatting (type not specified or =none)
	if(type == 0) {
		// Construct response
		std::string body = "";
		for (unsigned int i = 0; i < answer->size(); i++){ //for each pair in answer
			if (i % 15 == 0){
				//Just making it pretty
				body += "ts                  orig_ip           orig_port   resp_ip           resp_port   source_tag     proto   duration   orig_byts          resp_byts          conn_flags  orig_pkts   resp_pkts   uid\n";
			}
			body += answer->at(i).getKey()->toString() + "	" + answer->at(i).getValue()->toString() + "\n";
			delete answer->at(i).getKey();
			delete answer->at(i).getValue();
		}
		delete answer;
		debug(110, "answer: %s\n", body.c_str());
		return body;
	}
	//if the user wants more infomation in human readable formats
	else if ( type == 3 ) {
		// Construct response using verbose string functions
		debug(80, "verbose mode");
		std::string body = "";
		for (unsigned int i = 0; i < answer->size(); i++){ //for each pair in answer
			if (i % 15 == 0){
				//Just making it pretty
				body += "ts                  orig_ip           orig_port   resp_ip           resp_port   source_tag     proto   duration   orig_byts          resp_byts          conn_flags  orig_pkts   resp_pkts   uid\n";
			}
			body += answer->at(i).getKey()->toVerboseString() + "	" + answer->at(i).getValue()->toVerboseString() + "\n";
			delete answer->at(i).getKey();
			delete answer->at(i).getValue();
		}
		delete answer;
		debug(110, "answer: %s\n", body.c_str());
		return body;
	}
	//user wants json type=json
	else if (type == 1) {
		std::string body = "";
		//call specialized functions which return json formatted fields with the data
		//do this for each answer
		for( unsigned int i = 0; i < answer->size(); i++ ) {
			if( i == 0) {
			body += "{\"key\":{" + answer->at(i).getKey()->toJsonString() + "},";
			body += "\"value\":{" + answer->at(i).getValue()->toJsonString() + "}}";
			}
			else {
				body += ",{\"key\":{" + answer->at(i).getKey()->toJsonString() + "},";
				body += "\"value\":{" + answer->at(i).getValue()->toJsonString() + "}}";
			}
			delete answer->at(i).getKey();
			delete answer->at(i).getValue();
		}
		body = "[" + body + "]";
		debug(110, "answer: %s\n", body.c_str());
		delete answer;
		return body;
	}
	//user wants binary data type=bin
	else {
		std::string body = "";
		//call specialized functions which return the data in binary form
		//do this for each answer
		//Need to loop through each element because sometimes we have 0 data which is a null terminator
		for( unsigned int i = 0; i < answer->size(); i++ ) {
			Key *key = answer->at(i).getKey();
			Value *value = answer->at(i).getValue();
			char *keyStr = (char *)key->toBinary();
			char *valStr = (char *)value->toBinary();
			// debug(0, "key_bytes: %u\n", key->KEY_BYTES);
			for ( int x = 0; x < key->KEY_BYTES; x++ ) {
				body += keyStr[x];
			}
			//for ( int x = 0; x < value->VALUE_BYTES; x++ ) {
            for ( int x = 0; x < 28; x++ ) {
				body += valStr[x];
			}
			delete key;
			delete value;
		}
		debug(110, "answer: %s\n", body.c_str());
		delete answer;
		return body;
	}
}

/*
	Function which takes in the query and parses it for arguments 
	and returns a string map of argument types -> values
	This string map is called ret
*/
std::map<std::string, std::string> QuerySession::parseURLArgs(std::string url){
	std::map<std::string, std::string> ret;
	std::string name, value;
	size_t namePos, valuePos;

	debug(15, "parsing url '%s'\n", url.c_str());
	namePos = url.find("?");	// Find starting point of arguments
	while (namePos != std::string::npos){
		valuePos = url.find("=", namePos);	// Find end of key/start of value
		name = url.substr(namePos + 1, valuePos - namePos - 1);
		namePos = url.find("&", valuePos);	// Find end of value/start of next key
		value = url.substr(valuePos + 1, namePos - valuePos - 1);
		ret[name] = value;
		debug(15, "Url param '%s' = '%s'\n", name.c_str(), value.c_str());
	}

	return ret;
}

//Returns the requested formatting of the response
int QuerySession::type(std::map<std::string, std::string> &args) {
	if( args.count("type") != 0 ) {
		if ( args["type"] == "json" ) {
			return 1;
		}
		if ( args["type"] == "bin" ) {
			return 2;
		}
		if ( args["type"] == "verbose" ) {
			return 3;
		}
		debug(20, "WARN: Unrecongized formatting. Defaulting to normal\n");
	}
	return 0;
}

bool QuerySession::statistics(std::map<std::string, std::string> &args) {
	if( args.count("stats") != 0) {
		return true;
	}
	return false;
}
