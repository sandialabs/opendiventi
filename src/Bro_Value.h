/*
	Stores value for diventi. Values correspond to protocol, duration,
	number of bytes sent each way, connection state, and number of packets each way.
*/

#ifndef BRO_VALUE_BLOCK
#define BRO_VALUE_BLOCK

#include "diventi.h"
#include "Bro_Parse.h"
#include <tokudb.h>
#include <cstddef>


struct __toku_dbt;
typedef struct __toku_dbt DBT;

struct __toku_db;
typedef struct __toku_db DB;


class Bro_Value: public Value {
public:
	Bro_Value(uint8_t source, transProto protocol, uint32_t duration, int originBytes, int destinationBytes,
		connEnum connectionState, int originPackets, int destinationPackets, const char * uid);
	Bro_Value(DBT* dbt);
	Bro_Value(byte* data);
	Bro_Value(const Bro_Value& v);
	Bro_Value(const Value& v);
	~Bro_Value();
	DBT *getDBT() const;
	std::string getTag();
	transProto getProtocol();
	uint32_t getDuration();
	uint8_t getOrigBytes();
	uint8_t getRespBytes();
	connEnum getConnState();
	uint8_t getOrigPkts();
	uint8_t getRespPkts();
	char *  getUid();
	std::string toString();
	std::string toVerboseString();
	std::string toExtendedString();
	std::string toJsonString();

	Bro_Value *operator=(const Value *other);
	bool operator==(const Value& other);
	bool operator!=(const Value& other);

	// Some constants unique to bro.
	static int const BRO_UID_SIZE =  18;

private:

	const static int SOURCE_POS = 0;
	const static int PROTO_CONN_POS = SOURCE_POS + sizeof(uint8_t);
	const static int DURATION_POS = PROTO_CONN_POS + sizeof(uint8_t);
	const static int ORIGIN_BYTES_POS = DURATION_POS + sizeof(uint32_t);
	const static int DEST_BYTES_POS = ORIGIN_BYTES_POS + sizeof(uint8_t);
	// const int CONN_POS = DEST_BYTES_POS + sizeof(uint8_t);
	const static int ORIGIN_PKTS_POS = DEST_BYTES_POS + sizeof(uint8_t); //sizeof(connEnum);
	const static int DEST_PKTS_POS = ORIGIN_PKTS_POS + sizeof(uint8_t);
	const static int UID_POS = DEST_PKTS_POS + sizeof(uint8_t);
	const static std::size_t VALUE_SIZE = UID_POS + BRO_UID_SIZE;

	// Number of  bytes used in binary represenation of the data
	// as it is sent to queries.  This can be different from the
	// raw database encoding currently.
	const static int BYTES_FOR_BINARY_REP = 28;

        
	DBT dbt;
	byte vData[VALUE_SIZE];

	void packData (uint8_t source_id, transProto protocol, uint32_t duration, 
				   int originBytes, int destinationBytes,
				   connEnum connectionState, int originPackets, 
				   int destinationPackets, const char *uid);

};

#endif
