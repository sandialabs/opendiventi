//test toku on max ip and min ip
#include "diventi.h"
#include "Control.h"
#include "InsertThread.h"
#include "TokuHandler.h"
#include "KeyValuePair.h"
#include "IP_Key.h"
#include "Bro_Value.h"

#include <cfloat>
#include <climits>
#include <boost/filesystem.hpp>

#include <boost/asio.hpp>


int main(int argc, char* argv[]) {
	if (argc < 2){
		debug_level = 0;
	} else{
		debug_level = atoi(argv[1]);
	}

	debug(0, "\nStarting test_edge_case_query\n");
	int a = argc;
	argc = a;
	char** b = argv;
	a = (int) **b;
	a = (int) **argv;
	OPTIONS.dataBaseDir = "test";
	source *tmp = new source();

	tmp->logFormat = "bro";
	tmp->tag = "bro-data";
	tmp->inputDir = "suspiciousDir";

	OPTIONS.sources[1] = tmp;
	// setUpFormat();

	debug(10, "creating handlers\n");
	TokuHandler* handler = new TokuHandler();
	debug(10, "created handler\n");

	struct in_addr* zeroIp = new in_addr();
	struct in_addr* maxIp = new in_addr();

	inet_pton(AF_INET, "0.0.0.0", zeroIp);
	inet_pton(AF_INET, "255.255.255.255", maxIp);

	IP_Key zeroKey(zeroIp, 0, 0, zeroIp, 0);
	IP_Key zeroKeyCopy(zeroKey);

	IP_Key maxKey(maxIp, INT_MAX, USHRT_MAX, maxIp, USHRT_MAX, true);
	IP_Key maxKeyCopy(maxKey);

	Bro_Value testValue(1, EMPTY_PROTO, 0, 1, 2, EMPTY_CONN, 3, 4, "CYYoei3hy4TjVFL5Gc");
	Bro_Value testValueCopy(testValue);

	Bro_Value testValue2(1, EMPTY_PROTO, 5, 4, 3, EMPTY_CONN, 2, 1, "CYYoei3hy4");
	Bro_Value testValue2Copy(testValue2);

	debug(1, "Test Key: %s\n", zeroKeyCopy.toExtendedString().c_str());
	debug(1, "Test Value: %s\n", testValueCopy.toExtendedString().c_str());

	handler->put(zeroKeyCopy, testValueCopy);
	handler->put(maxKeyCopy, testValue2Copy);
	debug(10, "Test Key and Value inserted\n");

	debug(10, "Querier about to run.\n");
	std::vector<KeyValuePair>* response = handler->get(&zeroKey, &maxKey);
	debug(10, "querier ran\n");

	if(response == nullptr || response->empty()) {
		debug(0, "TEST FAILED\nQuery had empty or null response\n");
		return 0;
	}
	debug(1, "Test Key: %s\n", response->at(0).getKey()->toExtendedString().c_str());
	debug(1, "Test Value: %s\n", response->at(0).getValue()->toExtendedString().c_str());

	debug(1, "Test Key: %s\n", response->at(1).getKey()->toExtendedString().c_str());
	debug(1, "Test Value: %s\n", response->at(1).getValue()->toExtendedString().c_str());
	KeyValuePair zeroKeyPair = KeyValuePair(zeroKey, testValue);
	if(response->at(0) != zeroKeyPair) {
		debug(1, "TEST FAILED\nQuery first response is different from insert.\n");
		
		debug(1, "Test Key: %s\n", response->at(0).getKey()->toExtendedString().c_str());
		debug(1, "Test Value: %s\n", response->at(0).getValue()->toExtendedString().c_str());
		debug(1, "Zero Key: %s\n", zeroKeyPair.getKey()->toExtendedString().c_str());
		debug(1, "Value: %s\n", zeroKeyPair.getValue()->toExtendedString().c_str());

		debug(0, "TEST FAILED\nQuery first response is different from insert.\n");
		exit(1);
	}

	KeyValuePair maxKeyPair = KeyValuePair(maxKey, testValue2);
	if(response->at(1) != maxKeyPair) {
		debug(0, "TEST FAILED\nQuery second response is different from insert.\n");

		debug(1, "Test Key: %s\n", response->at(1).getKey()->toExtendedString().c_str());
		debug(1, "Test Value: %s\n", response->at(1).getValue()->toExtendedString().c_str());
		debug(1, "Max Key: %s\n", maxKeyPair.getKey()->toExtendedString().c_str());
		debug(1, "Value: %s\n", maxKeyPair.getValue()->toExtendedString().c_str());

		debug(1, "TEST FAILED\nQuery second response is different from insert.\n");
		exit(1);
	}
	delete handler;
	debug_level = 0;
	boost::filesystem::path processed(std::string(OPTIONS.dataBaseDir) + "/.Processed");
	boost::filesystem::remove_all(processed);
	debug(0, "TEST PASSED!\n");
}