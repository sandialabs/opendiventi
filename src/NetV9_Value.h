/*
	Stores value for diventi. Values correspond to protocol, duration,
	number of bytes sent each way, connection state, and number of packets each way.
*/

#ifndef NetV9_VALUE_BLOCK
#define NetV9_VALUE_BLOCK

#include "diventi.h"
#include "NetV9_Parse.h"
#include <tokudb.h>
#include <cstddef>


struct __toku_dbt;
typedef struct __toku_dbt DBT;

struct __toku_db;
typedef struct __toku_db DB;



class NetV9_Value: public Value {
public:
	NetV9_Value(uint8_t source, transProto protocol, uint32_t duration, int bytes,
		uint8_t flags, int packets);
	NetV9_Value(DBT* dbt);
	NetV9_Value(byte* data);
	NetV9_Value(const NetV9_Value& v);
	NetV9_Value(const Value& v);
	~NetV9_Value();
	DBT *getDBT() const;
	std::string getTag();
	transProto getProtocol();
	uint32_t getDuration();
	uint8_t getBytes();
	uint8_t getTcpFlags();
	std::string tcpStr();
	uint8_t getPkts();
	std::string toString();
	std::string toVerboseString();
	std::string toExtendedString();
	std::string toJsonString();
	std::string toBinary();
	NetV9_Value *operator=(const Value *other);
	bool operator==(const Value& other);
	inline bool operator!= (const Value& other) {return !(*this==other);}

	const static int num_flags = 6;
	static  std::string const  flagStr[num_flags];

private:
        static int const SOURCE_POS = 0;
        static int const PROTO_POS = SOURCE_POS + sizeof(uint8_t);
        static int const DURATION_POS = PROTO_POS + sizeof(uint8_t);
        static int const BYTES_POS = DURATION_POS + sizeof(uint32_t);
        static int const TCP_POS = BYTES_POS + sizeof(uint8_t);
        static int const PKTS_POS = TCP_POS + sizeof(uint8_t);

        static std::size_t const VALUE_SIZE = PKTS_POS + sizeof(uint8_t);

        // Number of  bytes used in binary represenation of the data
        // as it is sent to queries.  This can be different from the
        // raw database encoding currently.
        const int BYTES_FOR_BINARY_REP = 10;


        DBT dbt;
	byte vData[VALUE_SIZE];

	void packData (uint8_t source_id, transProto protocol, uint32_t duration,
					int bytes, uint8_t flags, int packets);
};

#endif
