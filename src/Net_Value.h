/*
	Stores value for diventi. Values correspond to protocol, duration,
	number of bytes sent each way, connection state, and number of packets each way.
*/

#ifndef NET_VALUE_BLOCK
#define NET_VALUE_BLOCK

#include "diventi.h"
#include "Net_Parse.h"
#include <tokudb.h>
#include <cstddef>


struct __toku_dbt;
typedef struct __toku_dbt DBT;

struct __toku_db;
typedef struct __toku_db DB;



class Net_Value: public Value {
public:
	Net_Value(uint8_t source, transProto protocol, uint32_t duration, int bytes,
		uint8_t flags, int packets);
	Net_Value(DBT* dbt);
	Net_Value(byte* data);
	Net_Value(const Net_Value& v);
	Net_Value(const Value& v);
	~Net_Value();
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
	uint8_t *toBinary();
	Net_Value *operator=(const Value *other);
	bool operator==(const Value& other);
	inline bool operator!= (const Value& other) {return !(*this==other);}

private:
        // Define some statics that are private to the Mon Value.
        // 
        //  static constants that will be kept for the class and
        //  accessable to all objects and their member functions.
        //
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
        static int const BYTES_FOR_BINARY_REP = 10;        


        DBT dbt;
	byte vData[VALUE_SIZE];

	void packData (uint8_t source_id, transProto protocol, uint32_t duration,
					int bytes, uint8_t flags, int packets);
};

#endif
