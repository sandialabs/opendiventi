//test the ablity of tokuhandler to correctly hold and return a log

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

	debug(0, "\nStarting test_single_query\n");
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

	IP_Key zeroKey(zeroIp, 0, 0, zeroIp, 0);
	IP_Key testKey(testIp, 123, 123, testIp, 123);
	IP_Key maxKey(maxIp, INT_MAX, USHRT_MAX, maxIp, USHRT_MAX, true);
	Bro_Value testValue(1, EMPTY_PROTO, 0, 1, 2, EMPTY_CONN, 3, 4, "CYYoei3hy4TjVFL5Gc");

	handler->put(testKey, testValue);
	debug(10, "Test Key and Value inserted\n");

	debug(10, "Querier about to run.\n");
	// // std::memcpy(tempDat
	std::vector<KeyValuePair>* response = handler->get(&zeroKey, &maxKey);
	debug(10, "querier ran\n");

	if(response == nullptr || response->empty()) {
		debug(1, "TEST FAILED\nQuery had empty or null response\n");
		exit(1);
	}

	testKey = IP_Key(testIp, 123, 123, testIp, 123);
	testValue = Bro_Value (1, EMPTY_PROTO, 0, 1, 2, EMPTY_CONN, 3, 4, "CYYoei3hy4TjVFL5Gc");

	debug(100, "\n%s\n%s\n%s\n%s\n", 
		response->front().getValue()->toString().c_str(),
		 testValue.toString().c_str(), 
		 response->front().getKey()->toString().c_str(),
		  testKey.toString().c_str());


	if(response->front() != KeyValuePair(testKey, testValue)) {
		debug(0, "TEST FAILED\nQuery response is different from insert.\n%s\n%s\n%s\n%s\n",
			response->front().getValue()->toString().c_str(),
			 testValue.toString().c_str(), 
			 response->front().getKey()->toString().c_str(),
			  testKey.toString().c_str());
		exitval = 1;
	} else {
		debug(0, "TEST PASSED!\n");
	}
	
	boost::filesystem::path processed(std::string(OPTIONS.dataBaseDir) + "/.Processed");
	boost::filesystem::remove_all(processed);

	delete handler;
	exit(exitval);
}