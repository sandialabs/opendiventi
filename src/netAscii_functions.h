#ifndef NETASCII_FUNCTIONS_BLOCK
#define NETASCII_FUNCTIONS_BLOCK

#include <string>
#include "diventi.h"

class logEntry;
class logFormat;
class DiventiStream;

class NetAscii: public AbstractLog {
public:
	void parse(std::string fields, logFormat *f);
	Key *createKey(DBT *dbt);
	Value *createValue(DBT *dbt);
	int parseBuf(char *buf, int size, logFormat **fp, std::list<logEntry *> *results);
	KeyValuePair *createPair( uint8_t index, std::list<logEntry *> *results, uint8_t source);
	bool parseFileFormat(std::string file, logFormat **format);
	int getRawData(char *buf, DiventiStream *stream);
	unsigned int getSyslogData(SyslogHandler *slh, char * buf, logFormat **fp);
	std::string getHeader();
	std::string getKey(std::string fileName);
	// Key *createFirstKey(std::map<std::string, std::string>&);
	// Key *createLastKey(std::map<std::string, std::string>&);
	logFormat *createFormat(std::string fields);
	std::string getStats();
};

#endif