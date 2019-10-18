// Passes and compiles

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

int main(int argc, char* argv[]) {
	if (argc < 2){
		debug_level = 0;
	} else{
		debug_level = atoi(argv[1]);
	}

	debug(0, "\nStarting test_range_server\n");
	OPTIONS.dataBaseDir = "test";
	OPTIONS.sources[1] = new source("bro", "bro-data", 0, "", "suspiciousDir", "", 0);
	Control* control = new Control(0);
	Server* server = new Server(9000,control, 1);
	server->run();

	int numTestRows = 1000;
	int numIncrementRows = 999;
	
	int numBadRows = 100;

	unsigned long lowerBound = 1000;
	unsigned long upperBound = 2 * lowerBound + numTestRows;
	
	struct in_addr* minIp = new in_addr();
	struct in_addr* maxIp = new in_addr();

	minIp->s_addr = htonl(lowerBound);
	maxIp->s_addr = htonl(upperBound);

	IP_Key minKey(minIp, 0, 0, minIp, 0);
	IP_Key minKeyCopy(minKey);

	IP_Key maxKey(maxIp, INT_MAX, USHRT_MAX, maxIp, USHRT_MAX, true);
	IP_Key maxKeyCopy(maxKey);

	const int PORT = 9000;

	std::vector<KeyValuePair> testPairs;
	std::vector<KeyValuePair> badPairs;

	char mins[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, minIp, mins, INET_ADDRSTRLEN);
	char maxs[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, maxIp, maxs, INET_ADDRSTRLEN);
	std::string target = "/query?ip=" + (std::string)mins + "&range=" + (std::string)maxs;
	std::string host = "0.0.0.0";


	// ClientsideCli* client = new ClientsideCli();
	//Make test rowsPORT
	for(int i = 0; i < numTestRows; i++) {
		struct in_addr* testIp = new in_addr();
		testIp->s_addr = htonl(lowerBound + i);
		IP_Key *testKey = new IP_Key(testIp, 0, 0, testIp, 0);
		Bro_Value *testValue = new Bro_Value(1, EMPTY_PROTO, 0, 1, 2, EMPTY_CONN, 3, 4, "CYYoei3hy4TjVFL5Gc");
		KeyValuePair testPair(*testKey, *testValue);
		testPairs.push_back(testPair);
	}

	//Make bad rows under the lower bound
	for(int i = 1; i <= numBadRows/2; i++) {
		struct in_addr* badIp = new in_addr();
		badIp->s_addr = htonl(lowerBound - i);

		IP_Key *badKey = new IP_Key(badIp, -1, -1, badIp, -1);
		Bro_Value *badValue = new Bro_Value(1, EMPTY_PROTO, -1, -2, i, EMPTY_CONN, -4, -5, "asdf");
		KeyValuePair badPair(*badKey, *badValue);
		badPairs.push_back(badPair);
	}

	//Make bad rows over the upper bound
	for(int i = 1; i <= numBadRows/2; i++) {
		struct in_addr* badIp = new in_addr();
		badIp->s_addr = upperBound + i;

		IP_Key *badKey = new IP_Key(badIp, -1, -1, badIp, -1);
		Bro_Value *badValue = new Bro_Value(1, EMPTY_PROTO, -1, -2, i, EMPTY_CONN, -4, -5, "asdf");
		KeyValuePair badPair(*badKey, *badValue);
		badPairs.push_back(badPair);
	}

	//Insert test rows
	for(int i = 0, j = 0; i < numTestRows; i++, j = (j + numIncrementRows)%numTestRows) {
		debug(99, "%d\n", j%numTestRows);
		IP_Key testKeyCopy(*testPairs.at(j).getKey());
		Bro_Value testValueCopy(*testPairs.at(j).getValue());
		control->TKhandler->put(testKeyCopy, testValueCopy);
		delete testPairs.at(j).getKey();
		delete testPairs.at(j).getValue();
	}

	std::string original = http_get(host, PORT, target);

	//Insert bad rows
	for(int i = 0; i < numBadRows; i++) {
		IP_Key badKeyCopy(*badPairs.at(i).getKey());
		Bro_Value badValueCopy(*badPairs.at(i).getValue());
		control->TKhandler->put(badKeyCopy, badValueCopy);
		delete badPairs.at(i).getKey();
		delete badPairs.at(i).getValue();
	}

	debug(10, "Test Keys and Values inserted\n");

	debug(10, "Querier about to run.\n");
	
	std::string updated = http_get(host, PORT, target);
	debug(10, "Query sent and response received\n");

	if(updated == "") {
		debug(0, "TEST FAILED\nQuery had empty or null response\nEnsure that you have an internet connection.");
		exit(1);
	}

	if(updated != original) {
		debug(0, "TEST FAILED\nQuery response is different from insert.\n");
		debug(10, "NEW: %s\n\n\n\n\n\n", updated.c_str());
		debug(10, "OLD: %s\n", original.c_str());
		exit(1);
	}
	delete server;
	boost::filesystem::path processed(std::string(OPTIONS.dataBaseDir) + "/.Processed");
	boost::filesystem::remove_all(processed);
	delete control;	
	debug(0, "TEST PASSED!\n");
}
