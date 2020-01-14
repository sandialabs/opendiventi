#ifndef TOKUHANDLER_INCLUDED_DIVENTI
#define TOKUHANDLER_INCLUDED_DIVENTI

#include <tokudb.h>
#include <string>
#include <fstream>
#include <map>

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
	void flushToFile();
	bool put(KeyValuePair* pair);
	bool put(const Key &key, const Value &value);

	Key *whichKey(DBT *dbt);
	// NEWFORMAT
	void setIPKey();
	void setBasicKey();

	Key *getFirstKey(std::map<std::string, std::string> &args);
	Key *getLastKey(std::map<std::string, std::string> &args);
	
	std::vector<KeyValuePair> *get(Key* start, Key* end, uint32_t numb=1000, DBT **cTrack=nullptr);
	std::string binaryGet(Key* start, Key* end, uint32_t *numFound, uint32_t numb=1000, DBT **cTrack=nullptr);

	std::string DBStat(std::fstream *file);
private:
	DB_ENV* env;
	DB* db;
	const char* DB_FILE = "diventiV4";
	const char* DEFAULT_DIR = "env";
	const int MAX_DB_FILENAME_LENGTH = 100;
	const int MAX_ENV_DIRNAME_LENGTH = 300;

	// we can only use one form of key per db,
	// as our db handler, tokuHandler will enforce this
	// NEWFORMAT
	bool IPKey = false;
	bool BasicKey = false;
};

#endif
