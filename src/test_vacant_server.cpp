//tests querying an empty database over the network
#include "diventi.h"
#include "Server.h"
#include "Control.h"
#include "TokuHandler.h"
#include "KeyValuePair.h"

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

	std::string target = "/query?ip=123.123.123.124";
	std::string host = "127.0.0.1";
	const int PORT = 9000;

	int exitval = 0;
	OPTIONS.dataBaseDir = "test";
	source *tmp = new source();

	tmp->logFormat = "bro";
	tmp->tag = "bro-data";
	tmp->inputDir = "suspiciousDir";

	OPTIONS.sources[1] = tmp;
	Control* control = new Control(0);
	Server* server = new Server(PORT,control, 1);
	server->run();
	
	std::string answer = http_get(host, PORT, target);

	if(answer == "") {
		debug(0, "TEST PASSED\n");
		exitval = 0;
	} else{
		debug(0, "TEST FAILED\n");
		exitval = 1;
	}

	debug(10, "\n\nDeleting control\n\n\n");
	delete control;
	boost::filesystem::path processed(std::string(OPTIONS.dataBaseDir) + "/.Processed");
	boost::filesystem::remove_all(processed);
	debug(10, "\n\nDeleting server\n\n");
	delete server;

	exit(exitval);
}