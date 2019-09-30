#ifndef BASIC_FUNCTIONS_BLOCK
#define BASIC_FUNCTIONS_BLOCK

#include <string>
#include <boost/asio.hpp>
#include "diventi.h"

class logEntry;
class logFormat;
class DiventiStream;
class SyslogHandler;

class Basic: public AbstractLog {
public:
	~Basic();
	Key *createKey(DBT *dbt);
	Value *createValue(DBT *dbt);
	int parseBuf(char *buf, int size, logFormat **fp, std::list<logEntry*> *results);
	KeyValuePair *createPair(uint8_t index, std::list<logEntry*> *results, uint8_t source);
	bool parseFileFormat(std::string file, logFormat **format);
	int getRawData(char *buf, DiventiStream *stream);
	unsigned int getSyslogData(SyslogHandler *slh, char * buf, logFormat **fp);
	std::string getHeader();
	std::string getKey(std::string fileName);
	logFormat *createFormat(std::string fields);
	std::string getStats() { return ""; }
};

#endif