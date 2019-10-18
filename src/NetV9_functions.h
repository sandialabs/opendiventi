#ifndef V9_FUNCTIONS_BLOCK
#define V9_FUNCTIONS_BLOCK

//HEADER positions:

const int VERSION 	= 0;
const int FLOWS 	= 2;
const int UNIXSEC 	= 4;
const int NANOSEC	= 8;
const int SEQ 		= 12;
const int S_ID		= 16;
const int HEAD_SIZE = 20;

#include <string>
#include <mutex>
#include "diventi.h"

class logEntry;
class logFormat;
class DiventiStream;
class SyslogHandler;
class NetV9_Format;

typedef struct data_buf {
	uint8_t *buffer;
	//2 << 13 = 2KB
	uint32_t size = 2<<13;
	uint32_t avail_size = 2<<13;
	uint32_t position = 0;
	data_buf() {
		buffer = (uint8_t *)malloc(size);
	}
	~data_buf() {
		free(buffer);
	}
} data_buf;

class NetV9: public AbstractLog {
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
	~NetV9();

	//mutex for getSyslogData and getRawData as multiple threads will be using them
	//and they require shared resources
	std::mutex mGet;

	//OPTION ONE: One buffer
	// 2^16 = 16Kb
	// static const uint buf_size = 2 <<16;
	// uint avail_stor = buf_size; //variable to keep track of the amount of storage left
	// uint write_pos = 0; //Pointer to where we should be writing
	// uint8_t data_buffer[buf_size]; //buffer for storing data flows that don't have templates yet

	//OPTION TWO: A map of ids to buffers, malloc/realloc as needed
	std::map<uint16_t, data_buf *> data_buffer;
	uint32_t numDropIPv6 = 0;
	uint32_t numDropVer = 0;
	uint32_t numDropTemplate = 0;
	uint32_t numDropTemplateFlows = 0;
	uint32_t numDropShort = 0;
	uint32_t numFlowDropShort = 0;

	//map from template IDs to formats
	std::map<uint16_t, NetV9_Format *> templates;
	std::map<uint16_t, NetV9_Format *> oldTemplates;
	// bool headerValid = true;

	//To do some basic caching keep track of the most recently used template
	uint16_t MRU_templateID = 0;
	NetV9_Format *MRU_template = nullptr;

	// uint16_t buffer_id = 0;

	//Global variables which define the relevant data for recieving data over udp
	const uint16_t sysMaxSize = ~0 - 1;
};

//std::string netAscii_formatResponse(std::vector <KeyValuePair> *answer, int type);

#endif