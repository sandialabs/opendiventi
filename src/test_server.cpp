#include "diventi.h"
#include "Control.h"
#include "Server.h"
#include "Bro_Value.h"
#include "IP_Key.h"
#include "TokuHandler.h"

#include <boost/filesystem.hpp>

int main(int argc, char* argv[]){
	if (argc < 2){	
		debug_level = 0;
	} else{
		debug_level = atoi(argv[1]);
	}
	debug(1, "Starting test_server\n");

	OPTIONS.dataBaseDir = "test";
	OPTIONS.sources[1] = new source("bro", "bro-data", 0, "", "suspiciousDir", "", 0);
	Control* control = new Control(0);
	Server* server = new Server(41311,control, 1);
	server->run();

	struct in_addr* testIp = new in_addr();
	inet_pton(AF_INET, "123.123.123.124", testIp);
	IP_Key* testKey = new IP_Key(testIp, 123000, 123, testIp, 123);
	Bro_Value* testValue = new Bro_Value (1, EMPTY_PROTO, 0, 1, 2, EMPTY_CONN, 3, 4, "CYYoei3hy4TjVFL5Gc");

	control->TKhandler->put(*testKey, *testValue);

	delete testIp;
	delete testKey;
	delete testValue;

	testIp = new in_addr();
	inet_pton(AF_INET, "123.255.123.121", testIp);
	testKey = new IP_Key(testIp, 255255, 1234, testIp, 1243);
	testValue = new Bro_Value (1, EMPTY_PROTO, 10, 22, 18, EMPTY_CONN, 30, 14, "CYYoei3hy4TjVFL5Gc");;

	control->TKhandler->put(*testKey, *testValue);

	delete testIp;
	delete testKey;
	delete testValue;
	

	debug(10, "\n\nDeleting control\n\n\n");
	delete control;
	boost::filesystem::path processed(std::string(OPTIONS.dataBaseDir) + "/.Processed");
	boost::filesystem::remove_all(processed);
	debug(10, "\n\nDeleting server\n\n");
	delete server;

	debug(10, "Deleted everything\n");
}