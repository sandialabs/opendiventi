//needs rewriting
#include "diventi.h"
#include "Control.h"
#include "Server.h"
#include "KeyValuePair.h"

#include <boost/filesystem.hpp>

int main(int argc, char* argv[]){
	if (argc < 2){	
		debug_level = 0;
	} else{
		debug_level = atoi(argv[1]);
	}

	int exitval = 0;
	OPTIONS.dataBaseDir = "test";
	OPTIONS.sources[1] = new source("bro", "bro-data", 0, "", "suspiciousDir", "", 0);
	Control* control = new Control(0);
	Server* server = new Server(9000,control, 1);
	server->run();

	sleep(1);
	//cut off the connection while server is still listening
	//This isn't really possible with the asynchronous relationship of queries
	debug(10, "\nDeleting control\n");
	delete control;
	boost::filesystem::path processed(std::string(OPTIONS.dataBaseDir));
	boost::filesystem::remove_all(processed);	
	debug(10, "\n\nDeleting server\n\n");
	delete server;
	debug(10, "Stuff deleted\n");

	debug(0, "TEST PASSED!\n");

	exit(exitval); //will break before this if the test fails
}
