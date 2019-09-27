#ifndef NETBINARY_FUNCTIONS_BLOCK
#define NETBINARY_FUNCTIONS_BLOCK

//HEADER positions:

const int VER 		= 0;
const int COUNT 	= 2;
const int UPTIME 	= 4;
const int SECS 		= 8;
const int NSECS		= 12;
const int FLOW_S	= 16;
const int E_TYPE	= 20;
const int E_ID		= 21;
const int S_INTER	= 22;

//FLOW positions:
const int SRC_IP	= 0;  //->3
const int DST_IP	= 4;  //->7
const int PKT 		= 16; //->19 (In packets, out packets=0)
const int BYT 		= 20; //->23 (In bytes, out bytes=0)
const int FIRST 	= 24; //->27
const int LAST 		= 28; //->31
//DURATION: LAST - FIRST
const int SRC_PORT 	= 32; //->33
const int DST_PORT 	= 34; //->35
const int FLAGS 	= 37;
const int PROT 		= 38;

#include <string>
#include <mutex>
#include "diventi.h"

class logEntry;
class logFormat;
class DiventiStream;
class SyslogHandler;

class NetV5: public AbstractLog {
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

//std::string netAscii_formatResponse(std::vector <KeyValuePair> *answer, int type);

#endif