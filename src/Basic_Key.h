#ifndef BASIC_KEY_BLOCK
#define BASIC_KEY_BLOCK

#include "diventi.h"

#include <tokudb.h>
#include <cstddef>

/*
	Stores key for diventi.
	Keys correspond to a pair of ips and ports and a time associated with a connection. 
*/

/* 
 *   A struct to define the raw data in the key.  This makes
 *   packing rather straight forward. 
 */
typedef struct BASIC_rawKey {
	uint32_t altitude;
} BASIC_rawKey_t;


//  key data union kd_u
//    A union to format the key data in two ways.
union basic_kd_u {
	byte data[BASIC_KEY_SIZE];
	BASIC_rawKey_t key;
};

class Basic_Key: public Key {
public:
	Basic_Key(uint32_t altitude);
	Basic_Key(DBT* dbt);
	Basic_Key(byte* data);
	Basic_Key(const Basic_Key& key);
	Basic_Key(const Key& key);
	~Basic_Key();
	DBT *getDBT() const;
	char *getDate(char *time) {return time;};
	uint32_t getAltitude();

	std::string toString();
	std::string toVerboseString();
	std::string toExtendedString();
	std::string toJsonString();
	uint8_t *toBinary();

	Basic_Key *operator=(const Key *other);
	bool operator==(const Key& other);
	bool operator!=(const Key& other);
	static Key *createFirstKey(std::map<std::string, std::string> &args);
	static Key *createLastKey(std::map<std::string, std::string> &args);

private:
	//DBT* dbt;
	DBT dbt;
	basic_kd_u keyData;

	void packData(uint32_t);
	// Assigned here so that we can have correct sizes without malloc'ing
	const int ALTITUDE_POS = 0;
	const std::size_t KEY_SIZE = ALTITUDE_POS + sizeof(uint32_t);

	const int KEY_MAX_CHAR_LENGTH = 500; 
	const int INIT_KEY_DATA_LEN = 64;

	const int KEY_LEN2 = sizeof(BASIC_rawKey);
};

#endif
