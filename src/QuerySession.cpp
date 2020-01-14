/*
 * Handles a single query session. Parses the query, constructs a response, and sends it back. 
 */

#include "diventi.h"
#include "Control.h"
#include "QuerySession.h"
#include "KeyValuePair.h"
#include "TokuHandler.h"

#include <boost/beast/version.hpp>
#include <boost/thread/thread.hpp>
#include <climits>
#include <chrono>
#include <fstream>

using tcp = boost::asio::ip::tcp;
namespace http = boost::beast::http;

typedef enum types : int{
	NORMAL, VERBOSE, JSON, BINARY
} types;

const std::string typeStr[4] = {"none", "verbose", "json", "bin"};

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
	// initialize the variable which tracks the time we recieved this query
	start = std::chrono::system_clock::now();

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

	// Construct query
	bool getStats;
	Key *startKey;
	Key *endKey;
	int type;
	int numberOfLogs;
	try{
		getStats = statistics(args);
		startKey = control->TKhandler->getFirstKey(args);
		debug(70, "starting key: %s", startKey->toExtendedString().c_str());
		endKey = control->TKhandler->getLastKey(args);
		debug(70, "end key: %s", endKey->toExtendedString().c_str());
		type = getType(args); //call the format function which returns whether json is to be used or not
		numberOfLogs = getNumber(args);
	} catch(std::invalid_argument &e){
		error(http::status::bad_request, "The server was unable to parse the arguments of your http request. Please try again.\n");
		debug(10, "Had error parsing arguments in http request\n");
		return;
	}
	// Query Tokuhandler
	std::vector <KeyValuePair> *answer; //answer is a ptr to a vector of KeyValuePairs
	// variable to track the position of our cursor within the db for the case where the number
	// of logs that match the query exceeds the number of logs requested by the user
	DBT** cTrack = (DBT **) calloc(1, sizeof(DBT*));

	std::string body;

	if(type == BINARY) {
		debug(70, "binary formatting\n");
		try{
			body = control->TKhandler->binaryGet(startKey, endKey, &numReturned, numberOfLogs, cTrack);
		} catch(std::runtime_error &e){ //if Tokuhandler throws a error 
			error(http::status::internal_server_error, "The server experienced an internal error. Please try again.\n");
			debug(10,"Had error processing query\n");
			return;
		}
	} else {
		try{
			answer = control->TKhandler->get(startKey, endKey, numberOfLogs, cTrack); //supply tokuhandler with the startKey and endKey and ask for data that fits
		} catch(std::runtime_error &e){ //if Tokuhandler throws a error 
			error(http::status::internal_server_error, "The server experienced an internal error. Please try again.\n");
			debug(10,"Had error processing query\n");
			return;
		}

		numReturned = answer->size();
		debug(30,"Found %u results\n",numReturned);
		//format the response
		body = formatRes(answer, type);
		debug(110, "answer: %s\n", body.c_str());
	}
	
	
	//If collecting statistics, append relevant information
	//This is as close as we can get, for benchmarking we'll calculate this later so times may be different
	std::chrono::duration<double> diff = std::chrono::system_clock::now() - start;
	if(getStats) {
		// For JSON we have to return in specialized format, otherwise just return string
		if(type == JSON) {
			// cut off ending ], add some more elements then add ] back on
			body = body.substr(0, body.length() - 2) + ",{\"fetch_time\":\""+std::to_string(diff.count())+"\"}";
			body += ",{\"count\":\"" + std::to_string(numReturned) + "\"}]";
		}
		else {
			body += "\n\nTime to get responses: " + std::to_string(diff.count()) + " Number returned: " + std::to_string(numReturned);
		}
	}

	// add the cursor link to the beginning of the body
	if(*cTrack != nullptr) {
		body = addLink(body, *cTrack, args, type);
		free((*cTrack)->data);
		delete *cTrack;
	}
	free(cTrack);

	// If browser request, maintain space formatting with html
	std::string agent = std::string(req[http::field::user_agent]);
	if (agent.find("Firefox") != std::string::npos  ||
		agent.find("Chrome") != std::string::npos   ||
		agent.find("Chromium") != std::string::npos ||
		agent.find("Safari") != std::string::npos   ||
		agent.find("Edge") != std::string::npos){

		body = "<pre>" + body + "</pre>";
	}
	debug(60, "user agent: %s\n", agent.c_str());

	delete startKey;
    delete endKey;

	debug(150,"%s\n", body.c_str());
	http::response<http::string_body> res{http::status::ok, req.version()};
	res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
	res.set(http::field::content_type, "text/html");
	res.keep_alive(req.keep_alive());
	res.body() = body;
	res.prepare_payload();
	send(res);
}

//Checks to ensure that the query actually has an ip address
bool QuerySession::validateQuery(std::map<std::string, std::string> &args){
	if (args.count("ip") == 0){
		// check if the user actually wants the sources. Either way return false because we aren't
		getSources(args);
		return false;
	}
	if (args.count("range") != 0 && args["range"] != args["ip"] && (args.count("startTime") != 0 || args.count("endTime") != 0)) {
		error(http::status::bad_request, "Invalid query... \"range\" cannot be used with time constraints. Send multiple queries or use post query filtering if this functionality is necessary.");
		return false;
	}

	return true;
}

void QuerySession::getSources(std::map<std::string, std::string> &args) {
	std::string src = "";
	if (args.count("sources") != 0) {
		// set up the string to return upon sources requests
		// NEWFORMAT add a string, if, and output for your format
		std::string bro_num = "";
		std::string mon_num = "";
		std::string v5_num = "";
		std::string v9_num = "";
		std::string netAscii_num = "";
		std::string basic_num = "";

		// loop through the sources to grab sources
		for (int i = 0; i < 256; i++) {
			if (OPTIONS.sources[i] != nullptr) {
				if (OPTIONS.sources[i]->logFormat == "bro") {
					bro_num += " " + std::to_string(i);
				}
				else if(OPTIONS.sources[i]->logFormat == "mon") {
					mon_num += " " + std::to_string(i);
				}
				else if(OPTIONS.sources[i]->logFormat == "NetV5") {
					v5_num += " " + std::to_string(i);
				}
				else if(OPTIONS.sources[i]->logFormat == "NetV9") {
					v9_num += " " + std::to_string(i);
				}
				else if(OPTIONS.sources[i]->logFormat == "netAscii") {
					netAscii_num += " " + std::to_string(i);
				}
				else if(OPTIONS.sources[i]->logFormat == "basic") {
					basic_num += " " + std::to_string(i);
				}
			}
		}
		src += "bro" + bro_num + "\n";
		src += "mon" + mon_num + "\n";
		src += "NetV5" + v5_num + "\n";
		src += "NetV9" + v9_num + "\n";
		src += "netAscii" + netAscii_num + "\n";
		src += "basic" + basic_num + "\n";
		
		// If browser request, maintain space formatting with html
		std::string agent = std::string(req[http::field::user_agent]);
		if (agent.find("Firefox") != std::string::npos  ||
			agent.find("Chrome") != std::string::npos   ||
			agent.find("Chromium") != std::string::npos ||
			agent.find("Safari") != std::string::npos   ||
			agent.find("Edge") != std::string::npos){

			src = "<pre>" + src + "</pre>";
		}

		http::response<http::string_body> res{http::status::ok, req.version()};
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = src;
		res.prepare_payload();
		send(res);
		return;
	}
	else {
		error(http::status::bad_request, "Invalid query... \"ip\" argument required to query database. Or use \"sources\" to return Diventi's current sources");
		return;
	}
}

/*	
	Evan - 06/21
	Function to format the result of the query
*/
std::string QuerySession::formatRes(std::vector <KeyValuePair> *answer, int type) {
	if (type == NORMAL) {
		debug(70, "normal formatting\n");
		// Construct response
		std::string body = answer->size() == 0?"":diventiHeader;
		for (unsigned int i = 0; i < answer->size(); i++){ //for each pair in answer
			if (i % 15 == 0 && i != 0){
				//Just making it pretty
				// != 0 because we already handled the first header above
				body += "\n" + diventiHeader;
			}
			body += "\n" + answer->at(i).getKey()->toString() + "   " + answer->at(i).getValue()->toString();
			delete answer->at(i).getKey();
			delete answer->at(i).getValue();
		}
		delete answer;
		return body;
	}
	else if (type == VERBOSE) {
		// Construct response using verbose string functions
		debug(70, "verbose formatting");
		std::string body = answer->size() == 0?"":diventiHeader;
		for (unsigned int i = 0; i < answer->size(); i++) { //for each pair in answer
			if (i % 15 == 0 && i != 0){
				//Just making it pretty
				// != 0 because we already handled the first header above
				body += "\n" + diventiHeader;
			}
			body += "\n" + answer->at(i).getKey()->toVerboseString() + "   " + answer->at(i).getValue()->toVerboseString();
			delete answer->at(i).getKey();
			delete answer->at(i).getValue();
		}
		delete answer;
		return body;
	}
	else { //JSON
		debug(70, "json formatting\n");
		std::string body = "";
		//call specialized functions which return json formatted fields with the data
		//do this for each answer
		for (unsigned int i = 0; i < answer->size(); i++) {
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
		delete answer;
		return body;
	}
}

/*
	Function which takes a DBT which is a position within a search (cursor)
	It then creates a hexidecimal representation of that cursor to use as the
	cursor argument and then creates a link to this cursor query using
	the user's existing query and the newly generated cursor.
*/
std::string QuerySession::addLink(std::string body, DBT *cTrack, std::map<std::string, std::string> &args, int type) {
	// create a hex string which represents the cursor dbt
	std::stringstream stream;
	stream << std::setfill('0');

	// loop through the bytes in the data
	for( uint i = 0; i < cTrack->size; i++) {
		stream << std::setw(2) << std::hex << (int)(((uint8_t *)cTrack->data)[i]);
	}
	// overwrite old cursor if it exists
	// either way create cursor argument
	args["cursor"] = stream.str();

	// create html link from the arguments
	std::string link = "/query?";
	for( std::map<std::string, std::string>::iterator it = args.begin(); it != args.end(); it++ ) {
		link += it->first;
		if( it->second != "" ) {
			link += "=" + it->second;
		}
		link += "&";
	}
	link = link.substr(0,link.length() - 1); //cut off last &

	// If browser request, make an actual html link
	std::string agent = std::string(req[http::field::user_agent]);
	if (agent.find("Firefox") != std::string::npos  ||
		agent.find("Chrome") != std::string::npos   ||
		agent.find("Chromium") != std::string::npos ||
		agent.find("Safari") != std::string::npos   ||
		agent.find("Edge") != std::string::npos){

		link = "<a href=\"" + link + "\">more results</a>";
	}

	// if json then return in json specific formatting
	if( type == JSON ) {
		return "[{\"next\":\"" + link + "\"}," + body.substr(1, body.length() - 1); 
	}
	// else
	return link + "\n" + body; //in binary format we identify the possible link with \n
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
		size_t start = namePos;
		valuePos = url.find("=", start);	// Find end of key/start of value
		namePos = url.find("&", start+1);	// Find end of value/start of next key
		// compare if namePos or valuePos is earlier
		// sometimes arguments don't have values so in this case namePos will be sooner
		if(valuePos < namePos) {
			name = url.substr(start + 1, valuePos - start - 1);
			value = url.substr(valuePos + 1, namePos - valuePos - 1);
			ret[name] = value;
			debug(15, "Url param '%s' = '%s'\n", name.c_str(), value.c_str());
		} else {
			name = url.substr(start +1, namePos - start - 1);
			ret[name] = ""; // no argument, its just here
			debug(15, "Url param '%s'\n", name.c_str());
		}
	}

	return ret;
}

//Returns the requested formatting of the response
int QuerySession::getType(std::map<std::string, std::string> &args) {
	if( args.count("type") != 0 ) {
		if ( args["type"] == typeStr[1] ) {
			return VERBOSE;
		}
		if ( args["type"] == typeStr[2] ) {
			return JSON;
		}
		if ( args["type"] == typeStr[3] ) {
			return BINARY;
		}
		debug(20, "WARN: Unrecongized formatting. Defaulting to normal\n");
	}
	return NORMAL;
}

int QuerySession::getNumber(std::map<std::string, std::string> &args) {
	int ret = 1000;
	if( args.count("logs") != 0 ) {
		ret = stoi(args["logs"]);
	}
	if(ret > 1000000) {
		ret = 1000000; //cap the number of logs returned at 1 million
	}
	return ret;
}

bool QuerySession::statistics(std::map<std::string, std::string> &args) {
	if( args.count("stats") != 0) {
		return true;
	}
	return false;
}

//send the result of the query to the user.
//Check that it suceeded using handleWrite
//Called by: resolveQuery
void QuerySession::send(http::response<http::string_body>& msg){
 	// Keep a shared ptr so we don't accidentally delete this too early
 	res = std::make_shared<http::response<http::string_body>>(msg);
 	
 	#ifdef BENCHMARK
 		std::chrono::duration<double> diff = std::chrono::system_clock::now() - start;
		std::fstream *file = control->getSampleFile();
		(*file) << "QUERY:" << std::string(req.target()) << ":" << std::to_string(diff.count()) << ":" << std::to_string(numReturned) << std::endl;
	#endif

 	http::async_write(*sock, *res,
 					boost::bind(&QuerySession::handleWrite, this, 
					boost::asio::placeholders::error,
					boost::asio::placeholders::bytes_transferred));
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
