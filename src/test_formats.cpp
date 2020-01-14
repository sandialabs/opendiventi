//Test the ability of diventi to return the correct result over the network using
//	All formats
//Formats are:
//	string
//	json
//	binary
//	nice (human readable time formatting)
#include "diventi.h"
#include "Server.h"
#include "Control.h"
#include "TokuHandler.h"
#include "KeyValuePair.h"
#include "IP_Key.h"
#include "Bro_Value.h"

#include <cfloat>
#include <boost/beast/core.hpp>
#include <boost/beast/version.hpp>
#include <boost/beast/http.hpp>
#include <boost/program_options.hpp>
#include <boost/date_time.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/filesystem.hpp>
#include <iostream>
#include <fstream>
#include <climits>

using tcp = boost::asio::ip::tcp; 
namespace http = boost::beast::http;
namespace bt = boost::posix_time;

std::string http_get(std::string host, short port, std::string target){
	std::string ret = "";
	try{
		int version = 11;

		// The io_context is required for all I/O
		boost::asio::io_context ioc;

		// These objects perform our I/O
		tcp::resolver resolver{ioc};
		tcp::socket socket{ioc};

		// Look up the domain name
		auto const results = resolver.resolve(tcp::endpoint(boost::asio::ip::address::from_string(host), port));

		// Make the connection on the IP address we get from a lookup
		boost::asio::connect(socket, results.begin(), results.end());

		// Set up an HTTP GET request message
		http::request<http::string_body> req{http::verb::get, target, version};
		req.set(http::field::host, host);
		req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

		// Send the HTTP request to the remote host
		http::write(socket, req);

		// This buffer is used for reading and must be persisted
		boost::beast::flat_buffer buffer;

		// Declare a container to hold the response
		http::response<http::dynamic_body> res;

		// Receive the HTTP response
		http::read(socket, buffer, res);
		ret = boost::beast::buffers_to_string(res.body().data());

		// Gracefully close the socket
		boost::system::error_code ec;
		socket.shutdown(tcp::socket::shutdown_both, ec);

		if(ec && ec != boost::system::errc::not_connected){
		    throw boost::system::system_error{ec};
		}

	}
	catch(std::exception const& e){
		std::cerr << "Error: " << e.what() << std::endl;
	}

	return ret;
}

int main(int argc, char* argv[]){
	if (argc < 2){	
		debug_level = 0;
	} else{
		debug_level = atoi(argv[1]);
	}
	debug(0, "\nStarting test_server_single_query\n");

	std::string target4String = "/query?ip=123.123.123.124";
	std::string target4Json = "/query?ip=123.123.123.124&type=json";
	std::string target4Binary = "/query?ip=123.123.123.124&type=bin";
	std::string target4Nice = "/query?ip=123.123.123.124&type=verbose";
	std::string host = "127.0.0.1";
	const int PORT = 9000;

	OPTIONS.dataBaseDir = "test";
	source *tmp = new source();

	tmp->logFormat = "bro";
	tmp->tag = "bro-data";
	tmp->inputDir = "suspiciousDir";

	OPTIONS.sources[1] = tmp;
	Control* control = new Control(0);
	Server* server = new Server(PORT,control, 1);
	server->run();

	struct in_addr* zeroIp = new in_addr();
	struct in_addr* testIp = new in_addr();
	struct in_addr* maxIp = new in_addr();

	inet_pton(AF_INET, "0.0.0.0", zeroIp);
	inet_pton(AF_INET, "123.123.123.124", testIp);
	inet_pton(AF_INET, "255.255.255.255", maxIp);

	IP_Key zeroKey(zeroIp, 0, 0, zeroIp, 0);
	IP_Key testKey(testIp, 123, 123, testIp, 123);
	IP_Key maxKey(maxIp, INT_MAX, USHRT_MAX, maxIp, USHRT_MAX, true);
	Bro_Value testValue(1, EMPTY_PROTO, 0, 1, 2, EMPTY_CONN, 3, 4, "CYYoei3hy4TjVFL5Gc");
	
	control->TKhandler->put(testKey, testValue);
	debug(10, "Test Key and Value inserted\n");

	control->TKhandler->put(zeroKey, testValue);
	control->TKhandler->put(maxKey, testValue);
	debug(10, "Decoy keys inserted\n");

	//Test string
	std::string answer = http_get(host, PORT, target4String);

	if(answer == "") {
		debug(1, "TEST FAILED\nQuery had empty or null response\nEnsure that you have an internet connection.");
		exit(1);
	}
	//Set up expected value
	testKey = IP_Key(testIp, 123, 123, testIp, 123);
	testValue = Bro_Value (1, EMPTY_PROTO, 0.0, 1, 2, EMPTY_CONN, 3, 4, "CYYoei3hy4TjVFL5Gc");;
	std::string expected = diventiHeader + "\n" + testKey.toString() + "   " + testValue.toString();
	//Test answer against expected
	if(answer != expected) {
		debug(0, "TEST FAILED\nQuery response for string is different from insert.\n");
		debug(0, "Expected: %s\n", expected.c_str());
		debug(0, "Answer  : %s\n", answer.c_str());
		delete control;
		boost::filesystem::path processed(std::string(OPTIONS.dataBaseDir) + "/.Processed");
		boost::filesystem::remove_all(processed);
		delete server;
		exit(1);
	} else {
		debug(0, "String: TEST PASSED!\n");
	}

	//Test Json
	answer = http_get(host, PORT, target4Json);
	//Create expected answer
	expected = "[{\"key\":{" + testKey.toJsonString() + "},"  + "\"value\":{" + testValue.toJsonString() + "}}]";
	//Test answer against expected
	if(answer != expected) {
		debug(0, "TEST FAILED\nQuery response for json is different from insert.\n");
		debug(0, "Expected: %s\n", expected.c_str());
		debug(0, "Answer  : %s\n", answer.c_str());
		delete control;
		boost::filesystem::path processed(std::string(OPTIONS.dataBaseDir) + "/.Processed");
		boost::filesystem::remove_all(processed);
		delete server;
		exit(1);
	} else {
		debug(0, "Json:   TEST PASSED!\n");
	}

	//Test binary
	answer = http_get(host, PORT, target4Binary);
	//Create expected answer
	expected = std::string((const char *)testKey.getDBT()->data, testKey.getDBT()->size) + std::string((const char *)testValue.getDBT()->data, testValue.getDBT()->size);
	// char *key = (char *)testKey.toBinary();
	// char *value = (char *)testValue.toBinary();
	// for ( int x = 0; x < testKey.KEY_BYTES; x++ ) {
	// 	expected += key[x];
	// }
	// for ( int x = 0; x < 28; x++ ) {
	// 	expected += value[x];
	// }
	//Test answer against expected
	if(answer != expected) {
		debug(0, "Binary: TEST FAILED\nQuery response for binary is different from insert.\n");
		debug(0, "Expected vs. Answer\n");
		debug(0, "size is: %s\n", expected.size() == answer.size()?"equal":"different");
		for( uint x = 0; x < expected.size(); x++ ) {
			debug(0, "%c vs. %c\n", expected.c_str()[x], answer.c_str()[x]);
		}
		delete control;
		boost::filesystem::path processed(std::string(OPTIONS.dataBaseDir) + "/.Processed");
		boost::filesystem::remove_all(processed);
		delete server;
		exit(1);
	} else {
		debug(0, "Binary: TEST PASSED!\n");
	}

	//Test verbose time formatting
	answer = http_get(host, PORT, target4Nice);

	if(answer == "") {
		debug(1, "TEST FAILED\nQuery had empty or null response\nEnsure that you have an internet connection.");
		exit(1);
	}
	//Set up expected value
	expected = diventiHeader + "\n" + testKey.toVerboseString() + "   " + testValue.toVerboseString();
	
	//Test answer against expected
	if(answer != expected) {
		debug(0, "TEST FAILED\nQuery response for nice string is different from insert.\n");
		debug(0, "Expected: %s\n", expected.c_str());
		debug(0, "Answer: %s\n", answer.c_str());
		delete control;
		boost::filesystem::path processed(std::string(OPTIONS.dataBaseDir) + "/.Processed");
		boost::filesystem::remove_all(processed);
		delete server;
		exit(1);
	} else {
		debug(0, "Verbose: TEST PASSED!\n");
	}

	debug(10, "\n\nDeleting control\n\n\n");
	delete control;
	boost::filesystem::path processed(std::string(OPTIONS.dataBaseDir) + "/.Processed");
	boost::filesystem::remove_all(processed);
	debug(10, "\n\nDeleting server\n\n");
	delete server;
	
	debug(10, "Stuff deleted\n");
}
