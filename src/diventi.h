#pragma once

#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <cstring>
#include "debug.h"
#include <exception>
#include <stdexcept>
#include <stdio.h>
#include <errno.h>
#include <list>
#include <tokudb.h>
#include <map>

#define diventi_error(fmt, ...) fprintf(stderr, "%s:%d: " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

// const int VERSION = 0;
const int MAX_LINE = 8192;

// source definition and default values
typedef struct source {
	// general information
	std::string logFormat       = "bro";
	std::string tag             = "";
	std::string defaultFields   = "#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents";
	// for reading from syslog
	ushort syslogPort           = 0;
	ushort syslogOffset         = 0;
	// std::string syslogSeperator = "\n";
	char syslogSeperator        = '\n';
	// for reading from files
	std::string inputDir        = "";
	std::string fNameFormat     = "conn.*\\.log(\\.gz)?";
	// for reading from kafka, not yet implemented
	ushort kafkaPort            = 0;
} source;

typedef struct startOptions{
	bool continuous 	                    = false;
	bool directIo 		                    = false;
	bool create 		                    = true;
	bool tokuThreaded 	                    = true;
	bool diventiThreaded                    = false;
	bool ipv6 			                    = false;
	// bool syslog 		                    = false;
  	short queryPort		                    = 41311;	// Default query port
	// short syslogPort	                    = 1514;	// Default syslog port +1000 so no root
	int insertThreads	                    = 3;
	uint32_t tokuCleanerPeriod              = 0;
	uint32_t tokuCleanerIterations          = 0;
	uint32_t tokuFanout                     = 16;
	TOKU_COMPRESSION_METHOD tokuCompression = TOKU_DEFAULT_COMPRESSION_METHOD;
	uint32_t tokuPagesize                   = 4194304;
	// the next two are for delaying the growth of the number of threads
	uint64_t threadBase                     = 10000000; //10 million
	float threadExp                         = 1.3;
	uint64_t cleanDelay                     = 10000000000; //10 billion
	unsigned long syslogBufsize             = 32768;
	uint64_t cacheSize                      = 0;  // cache size in GB
	const char* dataBaseDir                 = nullptr;
	// const char* inputDir 	= nullptr;
	// const char* fNameFormat = nullptr;
	// const char* logFormat    = "bro";
	// const char* syslogFields = nullptr;
	std::map<uint, source*> sources;
} startOptions;

typedef unsigned char byte;
extern startOptions OPTIONS;

class DiventiStream;
//found in Parse
class logFormat;
class logEntry;
class KeyValuePair;
class SyslogHandler;

//Define abstract classes for the later key and values to be built upon
class Key {
public:
	virtual ~Key() = 0;
	virtual DBT* getDBT() const = 0;
	virtual std::string toString() = 0;
	virtual std::string toVerboseString() = 0;
	virtual std::string toExtendedString() = 0;
	virtual std::string toJsonString() = 0;
	virtual Key *operator=(const Key *other) = 0;
	virtual bool operator==(const Key& other) = 0;
	virtual bool operator!=(const Key& other) = 0;
	int KEY_BYTES;
};

class Value {
    
public:
	virtual ~Value() = 0;
	virtual DBT* getDBT() const = 0;
	virtual std::string toString() = 0;
	virtual std::string toVerboseString() = 0;
	virtual std::string toExtendedString() = 0;
	virtual std::string toJsonString() = 0;

	// Need these operators for testing
	virtual Value *operator=(const Value *other) = 0; 
	virtual bool operator== (const Value& other) = 0; 
	virtual bool operator!= (const Value& other) = 0; 

	char getSource();

	// This should be static and private and only in concrete classes
	// int VALUE_BYTES;
       
};

//Defines what order to expect the data in and what order to apply parsing functions
class logFormat {
public:
	virtual std::string toString() const = 0;
	virtual ~logFormat() = 0;
	// virtual void parse(std::string) = 0;

	// operators needed for testing
	virtual bool operator==(const logFormat& other) = 0;
	inline bool operator!=(const logFormat& other){ return !(*this == other); }
	//virtual logFormat *operator=(const logFormat& other) = 0;

};

// A parsed entry
class logEntry{
public:
	// logEntry(char *buf, int size, logFormat *fp);
	virtual ~logEntry() = 0;
	// operators needed for testing
	virtual bool operator==( logEntry& other) = 0;
	inline bool operator!=( logEntry& other){ return !(*this == other); }
	// virtual logEntry *operator=(const logEntry& other) = 0;
	// virtual void parse(std::string line, logFormat *fp) = 0;
	// virtual void ParseBuf(char * buf, int size, logFormat *fp) = 0;
	virtual std::string toString() = 0;
};

//new Architecture using a abstract class to define the format specific funcitons
//ewest - 08/14/18
class AbstractLog {
public:
	virtual ~AbstractLog() = 0;
	virtual int getRawData (char *, DiventiStream *stream) = 0; // which parse function to use for turning a buffer into a logEntry
	virtual Key *createKey(DBT *) = 0;
	virtual Value *createValue(DBT *) = 0;
	virtual int parseBuf (char *, int, logFormat **, std::list<logEntry*>*) = 0; // read data and return the number of keyValuePairs to be created
	virtual KeyValuePair *createPair (uint8_t, std::list<logEntry*>*, uint8_t) = 0; // returns a keyValuePair generated from the logEntries created by parseBuf
	virtual bool parseFileFormat (std::string , logFormat **) = 0; // how to set the fields of the file based on formatting and structure
	virtual unsigned int getSyslogData (SyslogHandler *, char *, logFormat**) = 0; // Define how to get data from a udp port
	virtual std::string getHeader() = 0;
	virtual std::string getKey(std::string) = 0; // How to get a unique key from a file
	// virtual Key *createFirstKey(std::map<std::string, std::string>&) = 0;
	// virtual Key *createLastKey(std::map<std::string, std::string>&) = 0;
	virtual logFormat *createFormat(std::string) = 0;
	virtual std::string getStats() = 0;
};

typedef int (* comparer)(DB *, const DBT *, const DBT *);

// extern comparer keyCompare;
//NEWFORMAT if the new format creates a new key then write the function to compare those keys here
inline int keyCompare(DB* db __attribute__((__unused__)), const DBT *a, const DBT *b) {
	return memcmp(a->data, b->data, a->size);
}

// inline int BASIC_KeyCompare(DB* db __attribute__((__unused__)), const DBT *a, const DBT *b) {
// 	return memcmp(a->data, b->data, a->size);
// }

//
//  List out the different types of data sources supported.
//

/* typedef enum sourceType : uint8_t{  */
/*     BRO_CONN_SRC, MON_SRC, NETFLOW_SRC, NetV9_SRC */
/* } sourceType; */

//  Defining data source types
// static const uint8_t UNKNOWN_SRC = 0;
// static const uint8_t BRO_SRC = 1;
// static const uint8_t MON_SRC = 2;
// static const uint8_t NETFLOW_SRC = 3;
// static const uint8_t NetV9_SRC = 4;

// const std::string dataSources[5] = {"Unknown", "Bro", "Mon", "NetFlow", "IPFix"};


// Common Value stuff brought to the central place.
//   possibly a common value.h?
//
const int VAL_MAX_CHAR_LENGTH = 2000;


// Limited number of things proto can be; hence, enum
static const int num_proto = 5;

typedef enum transProto : uint8_t{ 
	EMPTY_PROTO, UNKNOWN_TRANSPORT, TCP, UDP, ICMP
} transProto;

const std::string protoStr[5] = {"-", "unknown",
                                 "tcp", "udp", "icmp"};


// Possibly part of a parse.h?

// Define the handler type that is function to parse a field
// and load it into an entry.

typedef int (*handler_t)(logEntry *e, char *field);

const std::string diventiHeader = "ts                  orig_ip           orig_port   resp_ip           resp_port    source_tag     proto   duration   orig_byts          resp_byts          conn_flags  orig_pkts   resp_pkts   uid";
