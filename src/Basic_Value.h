#ifndef BASIC_VALUE_BLOCK
#define BASIC_VALUE_BLOCK

#include "diventi.h"
#include <tokudb.h>
#include <cstddef>


struct __toku_dbt;
typedef struct __toku_dbt DBT;

struct __toku_db;
typedef struct __toku_db DB;




class Basic_Value: public Value {
public:
	Basic_Value(uint8_t source, const char *);
	Basic_Value(DBT* dbt);
	Basic_Value(byte* data);
	Basic_Value(const Basic_Value& v);
	Basic_Value(const Value& v);
	~Basic_Value();

	DBT *getDBT() const;

	char *  getObservation();
	std::string getTag();

	std::string toString();
	std::string toVerboseString();
	std::string toExtendedString();
	std::string toJsonString();


	Basic_Value *operator=(const Value *other);
	bool operator==(const Value& other);
	bool operator!=(const Value& other);

	const static int SOURCE_POS = 0;
	const static int OBS_POS = SOURCE_POS + sizeof(uint8_t);
	const static int OBS_SIZE = 40;
	const static std::size_t VALUE_SIZE = OBS_POS + OBS_SIZE;
private:
	DBT dbt;
	byte vData[VALUE_SIZE];

	void packData (uint8_t source, const char *);
};

#endif
