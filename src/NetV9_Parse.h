/*
 * Parse.h and Parse.cpp deal with all the parsing.
 * Uses an index->field mapping via enum.
 */
#ifndef NetV9_PARSE_INCLUDE_GUARD
#define NetV9_PARSE_INCLUDE_GUARD

#include "diventi.h"
#include <stdint.h>
#include <string>
#include <netinet/in.h>




class NetV9_Format: public logFormat {

    // Some static constants for this format.
    static int const MAX_FIELDS = 10; 



    //Field Values
    static int const BYTS		= 1;
    static int const PKTES		= 2;
    static int const PROTOCOL	= 4;
    static int const TCP_FLAGS	= 6;
    static int const SRC_PORT	= 7;
    static int const SRC_IP	= 8;
    static int const DST_PORT	= 11;
    static int const DST_IP	= 12;
    static int const START_M	= 152;
    static int const END_M		= 153;


    enum logField {
	TS, ID_ORIG_H, ID_ORIG_P,
	ID_RESP_H, ID_RESP_P, 
	PROTO, DURATION, BYTES, 
	TCP_FLAG, PKTS, 
	UNUSED, UNKNOWN
    };


    static  std::string  const fieldStr[12];


 public:
	//Flow-set constants
	static int const F_ID		= 0;
	static int const LENG		= 2;

	//Templete constants
	static int const T_ID		= 0; //With the flow id and length before it's actually 4
	static int const F_COUNT	= 2;


	NetV9_Format(uint8_t *, uint16_t *);
	NetV9_Format();
	logField type[MAX_FIELDS];
	int lastToken; // The last token we need to process.
	
	handler_t fieldHandler[MAX_FIELDS];
	uint16_t locations[MAX_FIELDS] = {0};
	uint16_t totalSize = 0;

	std::string toString() const;
	~NetV9_Format(){}

	NetV9_Format &operator=(const logFormat& other);
	bool operator==(const logFormat& other);
	inline bool operator!=( logFormat& other) {return !(*this==other);}

	uint16_t parseTemplate(uint8_t *buf);

};


// A parsed entry
class NetV9_Entry: public logEntry{
public:
	int64_t ts, duration;	// Microsecond precision
	transProto proto;

	uint8_t tcp_flags;

	struct in_addr	id_orig_h, id_resp_h;

	uint16_t id_orig_p, id_resp_p;
	int64_t bytes, pkts;

	// logEntry(char *buf, int size, logFormat *fp);
	NetV9_Entry();
        NetV9_Entry(const logEntry& other);
	~NetV9_Entry();
	//NetV9_Entry &operator=(const logEntry& other);

	bool operator==( logEntry& other);
	inline bool operator!=( logEntry& other) {return !(*this==other);}

	// void parse(std::string line, logFormat *fp);
	// void parseBuf(char * buf, int size, logFormat *fp);
	std::string toString();

};

#if 1
// TODO - tmk - do these need to be here?
int TimeHandler(logEntry *e, char *s);
int OIPHandler(logEntry *e, char *s);
int OPortHandler(logEntry *e, char *s);
int RIPHandler(logEntry *e, char *s);
int RPortHandler(logEntry *e, char *s);
int ProtoHandler(logEntry *e, char *s);
int DurHandler(logEntry *e, char *s);
int BytesHandler(logEntry *e, char *s);
int FlagsHandler(logEntry *e, char *s);
int PktsHandler(logEntry *e, char *s);
#endif

#endif
