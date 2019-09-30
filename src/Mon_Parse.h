#ifndef MON_PARSE_BLOCK
#define MON_PARSE_BLOCK

#include "diventi.h"
#include <stdint.h>
#include <string>
#include <netinet/in.h>

const int MAX_MON_FIELDS = 13; 



class MonFormat: public logFormat {
public:
	//MonFormat();
        MonFormat(transProto p);
	std::string toString() const;
	~MonFormat(){}

        // The number of tokens needed and the list of handlers for each field
        // In the case of mon these are statically set as the class is created.
        int lastToken; // The last token we need to process.
        handler_t fieldHandler[MAX_MON_FIELDS];

        // what protocol we are currently parsing.
        transProto mon_proto = UNKNOWN_TRANSPORT;

	bool operator==(const logFormat& other);
	inline bool operator!=(const logFormat& other){ return !(*this == other); }
	MonFormat *operator=(const logFormat& other);

private:

        
};


// A parsed entry
class MonEntry: public logEntry{
public:
        int64_t ts;   // Time in seconds since epoch
	int32_t duration;  // initial value of -1 is why we're not unsigned.
        uint8_t connFlags;
        transProto proto;
	struct in_addr	id_orig_h, id_resp_h;

	uint16_t id_orig_p, id_resp_p;
	int64_t orig_bytes, resp_bytes;
	bool local_orig, local_resp;

	// logEntry(char *buf, int size, logFormat *fp);
	MonEntry();
	~MonEntry();
	bool operator==( logEntry& other);
	inline bool operator!=( logEntry& other){ return !(*this == other); }
	MonEntry *operator=(const logEntry& other);
	// void parse(std::string line, logFormat *fp);
	//void parseBuf(char * buf, int size, logFormat *fp);
        std::string connFlagtoString();
	std::string toString();
};

#endif
