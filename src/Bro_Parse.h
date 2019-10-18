#ifndef BRO_PARSE_BLOCK
#define BRO_PARSE_BLOCK

#include "diventi.h"
#include <stdint.h>
#include <string>
#include <netinet/in.h>


// Should these be moved into the class definition.

const int MAX_FIELDS = 35; 

typedef enum logField {
	TS, UID, ID_ORIG_H, ID_ORIG_P,
	ID_RESP_H, ID_RESP_P, PROTO,
	SERVICE, DURATION, 
	ORIG_BYTES, RESP_BYTES,
	CONN_STATE, LOCAL_ORIG,
	LOCAL_RESP, MISSED_BYTES,
	HISTORY, ORIG_PKTS,
	ORIG_IP_BYTES, RESP_PKTS,
	RESP_IP_BYTES, TUNNEL_PARENTS,
	ORIG_L2_ADDR, RESP_L2_ADDR,
	VLAN, INNER_VLAN, UNUSED,
	UNKNOWN
} logField;



const std::string fieldStr[27] = {"ts", "uid", "id.orig_h", "id.orig_p",
					"id.resp_h", "id.resp_p", "proto",
					"service", "duration", "orig_bytes",
					"resp_bytes", "conn_state", "local_orig",
					"local_resp", "missed_bytes", "history",
					"orig_pkts", "orig_ip_bytes", "resp_pkts",
					"resp_ip_bytes", "tunnel_parents", "orig_l2_addr",
					"resp_ls_addr", "vlan", "inner_vlan",
					"UNUSED", "UNKNOWN"};


// Limited number of things conn_state can be; hence, enum
static const int num_conn = 15;
typedef enum connEnum : uint8_t{
	EMPTY_CONN, S0, S1, SF, REJ, S2,
	S3, RSTO, RSTR, RSTOS0, RSTRH,
	SH, SHR, OTH, UNKNOWN_CONN
} connEnum;
const std::string connStr[15] = {"-", "S0", "S1", "SF", "REJ", "S2",
								 "S3", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH",
								 "SHR", "OTH", "UNKNOWN"};

class BroFormat: public logFormat {
public:
	BroFormat(std::string fields);
	BroFormat();
	logField type[MAX_FIELDS];
	int lastToken; // The last token we need to process.
	
	handler_t fieldHandler[MAX_FIELDS];

	std::string toString() const;
	~BroFormat(){}

	bool operator==(const logFormat& other);
	inline bool operator!=(const logFormat& other){ return !(*this == other); }
	BroFormat *operator=(const logFormat& other);
	void parse(std::string fields);
};


// A parsed entry
class BroEntry: public logEntry{
public:
	int64_t ts, duration;	// Microsecond precision
	transProto proto;
	connEnum conn_state;

	// would run better if static strings with fixed size
	std::string  service, history,
				orig_l2_addr, resp_l2_addr, tunnel_parents;

	struct in_addr	id_orig_h, id_resp_h;

	char uid[18];
	uint16_t id_orig_p, id_resp_p;
	int64_t orig_bytes, resp_bytes, missed_bytes, 
			 orig_pkts, orig_ip_bytes, resp_pkts,
			 resp_ip_bytes;
	bool local_orig, local_resp;
	int vlan, inner_vlan;

	// logEntry(char *buf, int size, logFormat *fp);
	BroEntry();
	~BroEntry();
	bool operator==( logEntry& other);
	inline bool operator!=( logEntry& other){ return !(*this == other); }
	BroEntry *operator=(const logEntry& other);
	// void parse(std::string line, logFormat *fp);
	//void parseBuf(char * buf, int size, logFormat *fp);
	std::string toString();
};

#endif
