// Put a bunch of indices within a certain range which is queried and place indicies outside this range
// Both above and below and then query to verify that this result is what was expected.
#include "diventi.h"
#include "InsertThread.h"
#include "TokuHandler.h"
#include "KeyValuePair.h"
#include "IP_Key.h"
#include "Bro_Value.h"
#include "Control.h"
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

	debug(0, "\nStarting test_range_query\n");
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
	debug(10, "creating handler\n");
	TokuHandler* handler = new TokuHandler();
	debug(10, "created handler\n");

	int numTestRows = 1000;
	int numIncrementRows = 999;
	
	int numBadRows = 100;

	unsigned long lowerBound = 100;
	unsigned long upperBound = 2 * lowerBound + numTestRows;
	
	struct in_addr* minIp = new in_addr();
	struct in_addr* maxIp = new in_addr();

	minIp->s_addr = htonl(lowerBound);
	maxIp->s_addr = htonl(upperBound);

	IP_Key minKey(minIp, 0, 0, minIp, 0);
	IP_Key minKeyCopy(minKey);

	IP_Key maxKey(maxIp, INT_MAX, USHRT_MAX, maxIp, USHRT_MAX, true);
	IP_Key maxKeyCopy(maxKey);
	debug(30, "Min key:\n%s\n\n", minKey.toExtendedString().c_str());
	debug(30, "Max key:\n%s\n\n", maxKey.toExtendedString().c_str());

	std::vector<KeyValuePair> testPairs;
	std::vector<KeyValuePair> badPairs;

	//Make test rows
	for(int i = 0; i < numTestRows; i++) {
		struct in_addr* testIp = new in_addr();
		testIp->s_addr = htonl(lowerBound + i);

		IP_Key *testKey = new IP_Key(testIp, 0, 0, testIp, 0);
		Bro_Value *testValue = new Bro_Value(1, EMPTY_PROTO, 0, 1, 2, EMPTY_CONN, 3, 4, "CYYoei3hy4TjVFL5Gc");
		KeyValuePair testPair(*testKey, *testValue);
		testPairs.push_back(testPair);
	}
	debug(30, "Sample test key:\n%s\n\n", testPairs[0].getKey()->toExtendedString().c_str());
	debug(30, "Sample test key:\n%s\n\n", testPairs[2].getKey()->toExtendedString().c_str());

	//Make bad rows under the lower bound
	for(int i = 1; i <= numBadRows/2; i++) {
		struct in_addr* badIp = new in_addr();
		badIp->s_addr = lowerBound - i;

		IP_Key *badKey = new IP_Key(badIp, -1000000, -1, badIp, -1);
		Bro_Value *badValue = new Bro_Value(1, EMPTY_PROTO, -1000000, -2, i, EMPTY_CONN, -4, -5, "asdf");
		KeyValuePair badPair(*badKey, *badValue);
		badPairs.push_back(badPair);
	}
	debug(30, "Sample bad key:\n%s\n\n", badPairs[0].getKey()->toExtendedString().c_str());

	//Make bad rows over the upper bound
	for(int i = 1; i <= numBadRows/2; i++) {
		struct in_addr* badIp = new in_addr();
		badIp->s_addr = htonl(upperBound + i);

		IP_Key *badKey = new IP_Key(badIp, -1000000, -1, badIp, -1);
		Bro_Value *badValue = new Bro_Value(1, EMPTY_PROTO, -1000000, -2, i, EMPTY_CONN, -4, -5, "asdf");
		KeyValuePair badPair(*badKey, *badValue);
		badPairs.push_back(badPair);
	}

	//Insert test rows
	for(int i = 0, j = 0; i < numTestRows; i++, j = (j + numIncrementRows)%numTestRows) {
		IP_Key testKeyCopy(*testPairs.at(j).getKey());
		Bro_Value testValueCopy(*testPairs.at(j).getValue());
		handler->put(testKeyCopy, testValueCopy);
	}

	//Insert bad rows
	for(int i = 0; i < numBadRows; i++) {
		IP_Key badKeyCopy(*badPairs.at(i).getKey());
		Bro_Value badValueCopy(*badPairs.at(i).getValue());
		handler->put(badKeyCopy, badValueCopy);
		delete badPairs.at(i).getKey();
		delete badPairs.at(i).getValue();
	}

	debug(10, "Test Keys and Values inserted\n");

	debug(10, "Querier about to run.\n");
	std::vector<KeyValuePair>* response = handler->get(&minKey, &maxKey);
	debug(10, "querier ran\n");

	if(response == nullptr || response->empty()) {
		debug(0, "TEST FAILED\nQuery had empty or null response\n");
		exit(1);
	}

	int cd = 10;
	for(int i = 0; i < numTestRows; i++) {
		KeyValuePair correctKeyPair = testPairs.at(i);
		if(response->at(i) != correctKeyPair) {
			debug(0, "TEST FAILED\nQuery response %d is different from insert.\n", i);
			
			debug(1, "Test Key:\n%s\n", response->at(i).getKey()->toExtendedString().c_str());
			debug(1, "Test Value:\n%s\n", response->at(i).getValue()->toExtendedString().c_str());

			debug(0, "Correct Key:\n%s\n", correctKeyPair.getKey()->toExtendedString().c_str());
			debug(0, "Correct Value:\n%s\n", correctKeyPair.getValue()->toExtendedString().c_str());

			// debug(0, "TEST FAILED\nQuery response %d is different from insert.\n", i);
			if (!--cd){
				exit(1);
			}
		}
		delete testPairs.at(i).getKey();
		delete testPairs.at(i).getValue();
	}

	// delete querier;
	debug(10, "querier deleted\n");
	delete handler;
	boost::filesystem::path processed(std::string(OPTIONS.dataBaseDir) + "/.Processed");
	boost::filesystem::remove_all(processed);
	debug_level = 0;
	debug(0, "TEST PASSED!\n");
}