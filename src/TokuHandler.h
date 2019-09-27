#ifndef TOKUHANDLER_INCLUDED_DIVENTI
#define TOKUHANDLER_INCLUDED_DIVENTI

#include <tokudb.h>
#include <string>
#include <fstream>

class Value;
class Key;
class KeyValuePair;
class AbstractLog;




#include <vector>


/*
	Holds handle to ft-index env and db(s). Has methods for interacting with ft-index. 
*/

class TokuHandler {
public:
	TokuHandler();
	~TokuHandler();
	void enableCleaner();
	bool put(KeyValuePair* pair);
	bool put(const Key &key, const Value &value);
	std::vector<KeyValuePair>* get(Key* start, Key* end);

	std::string DBStat(std::fstream *file);
private:
	DB_ENV* env;
	DB* db;
	//TODO need db6
	const char* DB_FILE = "diventiV4";
	const char* DEFAULT_DIR = "env";
	const int MAX_DB_FILENAME_LENGTH = 100;
	const int MAX_ENV_DIRNAME_LENGTH = 300;
};

#endif
