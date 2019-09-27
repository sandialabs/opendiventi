/*
 * Parse.h and Parse.cpp deal with all the parsing.
 * Uses an index->field mapping via enum.
 */
#ifndef NET_PARSE_INCLUDE_GUARD
#define NET_PARSE_INCLUDE_GUARD

#include "diventi.h"
#include <stdint.h>
#include <string>
#include <netinet/in.h>





class NetFormat: public logFormat {
    static int const MAX_FIELDS = 12; 

    enum logField {
        TS, ID_ORIG_H, ID_ORIG_P,
        ID_RESP_H, ID_RESP_P, 
        PROTO, DURATION, BYTES, 
        TCP_FLAG, PKTS, 
        UNUSED, UNKNOWN
    };


public:
	NetFormat(std::string fields);
	NetFormat();
	logField type[MAX_FIELDS];
	int lastToken; // The last token we need to process.
	
	handler_t fieldHandler[MAX_FIELDS];

	std::string toString() const;
	~NetFormat(){}

	bool operator==(const logFormat& other);
	inline bool operator!=(const logFormat& other){ return !(*this == other); }
	NetFormat *operator=(const logFormat& other);
	void parse(std::string fields);

private:

        const std::string fieldStr[MAX_FIELDS] = {"ts", "id.orig_h", "id.orig_p",
                                  "id.resp_h", "id.resp_p", "proto",
                                  "duration", "bytes", "tcp_flags",
                                  "pkts", "UNUSED", "UNKNOWN"};;
};




// A parsed entry
class NetEntry: public logEntry{
public:
	int64_t ts, duration;	// Microsecond precision
	transProto proto;

	uint8_t tcp_flags;

	struct in_addr	id_orig_h, id_resp_h;

	uint16_t id_orig_p, id_resp_p;
	int64_t bytes, pkts;

	// logEntry(char *buf, int size, logFormat *fp);
	NetEntry();
	~NetEntry();
	bool operator==( logEntry& other);
	NetEntry *operator=(const logEntry& other);
	// void parse(std::string line, logFormat *fp);
	//void parseBuf(char * buf, int size, logFormat *fp);
	std::string toString();

};

#endif
