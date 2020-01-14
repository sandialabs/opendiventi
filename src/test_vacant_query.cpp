//Tests querying an empty database
#include "diventi.h"
#include "Control.h"
#include "InsertThread.h"
#include "TokuHandler.h"
#include "KeyValuePair.h"
#include "IP_Key.h"
#include "Bro_Value.h"
#include "Bro_Parse.h"

#include <cfloat>
#include <climits>
#include <boost/filesystem.hpp>


int main(int argc, char* argv[]) {
	if (argc < 2){
		debug_level = 0;
	} else{
		debug_level = atoi(argv[1]);
	}

	int exitval = 0;


	source *tmp = new source();

	tmp->logFormat = "bro";
	tmp->tag = "bro-data";
	tmp->inputDir = "suspiciousDir";

	OPTIONS.sources[1] = tmp;
	// setUpFormat();

	debug(0, "\nStarting test_vacant_query\n");
	int a = argc;
	argc = a;
	char** b = argv;
	a = (int) **b;
	a = (int) **argv;
	OPTIONS.dataBaseDir = "test";

	debug(10, "creating handler\n");
	TokuHandler* handler = new TokuHandler();
	debug(10, "created handler\n");
	
	struct in_addr* zeroIp = new in_addr();
	struct in_addr* testIp = new in_addr();
	struct in_addr* maxIp = new in_addr();

	inet_pton(AF_INET, "0.0.0.0", zeroIp);
	inet_pton(AF_INET, "123.123.123.123", testIp);
	inet_pton(AF_INET, "255.255.255.255", maxIp);

	IP_Key* zeroKey = new IP_Key(zeroIp, 0, 0, zeroIp, 0);
	IP_Key* testKey = new IP_Key(testIp, 123.0, 123, testIp, 123);
	IP_Key* maxKey = new IP_Key(maxIp, INT_MAX, USHRT_MAX, maxIp, USHRT_MAX, true);
	Bro_Value* testValue = new Bro_Value (1, EMPTY_PROTO, 0, 1, 2, EMPTY_CONN, 3, 4, "CYYoei3hy4TjVFL5Gc");

	byte tempData[2*IP_Key::KEY_SIZE];
	std::memcpy(tempData, zeroKey->getDBT()->data, IP_Key::KEY_SIZE);
	std::memcpy(tempData+IP_Key::KEY_SIZE, maxKey->getDBT()->data, IP_Key::KEY_SIZE);

	debug(10, "Querier about to run.\n");
	std::vector<KeyValuePair>* response = handler->get(zeroKey, maxKey);
	debug(10, "querier ran\n");

	delete zeroKey;
	debug(99, "ZeroKey deleted\n");
	delete testKey;
	debug(99, "TestKey deleted\n");
	delete maxKey;
	debug(99, "MaxKey deleted\n");
	delete testValue;
	debug(10, "keys and values deleted\n");

	if(response == nullptr) {
		debug(0, "TEST FAILED! \nQuery had null response\n");
	} else if(response->empty()) {
		debug(0, "TEST PASSED!\n");
	}else{

		testKey = new IP_Key(testIp, 123, 123, testIp, 123);
		testValue = new Bro_Value (1, EMPTY_PROTO, 0, 1, 2, EMPTY_CONN, 3, 4, "CYYoei3hy4TjVFL5Gc");

		debug(100, "\n%s\n%s\n%s\n%s\n", 
			response->front().getValue()->toString().c_str(),
			 testValue->toString().c_str(), 
			 response->front().getKey()->toString().c_str(),
			  testKey->toString().c_str());


		if(response->front() != KeyValuePair(*testKey, *testValue)) {
			debug(100, "\n%s\n%s\n%s\n%s\n", 
				response->front().getValue()->toString().c_str(),
				 testValue->toString().c_str(), 
				 response->front().getKey()->toString().c_str(),
				  testKey->toString().c_str());
			exitval = 1;
		} else {
			debug(0, "TEST FAILED!");
			exitval = 1;
		}

		delete testValue;
		delete testKey;
	}

	delete zeroIp;
	delete testIp;
	delete maxIp;
	boost::filesystem::path processed(std::string(OPTIONS.dataBaseDir) + "/.Processed");
	boost::filesystem::remove_all(processed);
	delete handler; //this deletes tokuhandler
	exit(exitval);
}