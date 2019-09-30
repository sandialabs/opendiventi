/*
	Stores value for diventi. Values correspond to protocol, duration,
	number of bytes sent each way, connection state, and number of packets each way.
*/

#ifndef MON_VALUE_BLOCK
#define MON_VALUE_BLOCK

#include "diventi.h"
#include <tokudb.h>
#include <cstddef>



//#include "Mon_Parse.h"



// TODO -- visit why this is here?  Should this come from a common header?
struct __toku_dbt;
typedef struct __toku_dbt DBT;

struct __toku_db;
typedef struct __toku_db DB;


class Mon_Value: public Value {
public:
        Mon_Value(uint8_t source, transProto proto, uint32_t duration, int originBytes, int respBytes,
		uint8_t connFlags);
	Mon_Value(DBT* dbt);
	Mon_Value(byte* data);
	Mon_Value(const Mon_Value& v);
	Mon_Value(const Value& v);
	~Mon_Value();
	DBT *getDBT() const;
        std::string getTag();
	transProto getProtocol();
	uint32_t getDuration();
	uint8_t getOrigBytes();
	uint8_t getRespBytes();
	uint8_t getConnFlags();
	std::string toString();
	std::string toVerboseString();
	std::string toExtendedString();
	std::string toJsonString();
	uint8_t *toBinary();
	Mon_Value *operator=(const Value *other); 
	bool operator==(const Value& other); 
	bool operator!=(const Value& other); 


        
        // Set up bits within a byte to list the flags that Mon provides
        //   It might make sense that these are in a higher class like
        //   MonLogFormat or such. But for now since they are part of
        //   the data that Value needs I'm moving them to value. tmk-2019-03-15
        const static int num_flags = 6;
        enum flagEnum : uint8_t { MON_SYN_FLAG=0,
                        MON_SYN2_FLAG, MON_ACK_FLAG, MON_DATA_FLAG,
                        MON_FIN_FLAG, MON_RESET_FLAG
                        };

 
        static  std::string const  flagStr[num_flags];


private:

        // Define some statics that are private to the Mon Value.
        // 
        //  static constants that will be kept for the class and
        //  accessable to all objects and their member functions.
        // 
        static int const SOURCE_POS =0;
        static int const PROTO_POS = SOURCE_POS + sizeof(uint8_t);
        static int const DURATION_POS = PROTO_POS + sizeof(uint8_t);
        static int const ORIGIN_BYTES_POS = DURATION_POS + sizeof(uint32_t);
        static int const RESP_BYTES_POS = ORIGIN_BYTES_POS + sizeof(uint8_t);
        static int const FLAGS_POS = RESP_BYTES_POS  + sizeof(uint8_t);

        static std::size_t const VALUE_SIZE = FLAGS_POS +  + sizeof(uint8_t);

        // Number of  bytes used in binary represenation of the data
        // as it is sent to queries.  This can be different from the
        // raw database encoding currently.
        static int const BYTES_FOR_BINARY_REP = 10;        

        
        // Instance variables        
        DBT dbt;
	byte vData[VALUE_SIZE];
        
        std::string connFlagtoString(uint8_t flags);        
	void packData (uint8_t src, transProto p, uint32_t duration, int originBytes,
		       int respBytes, uint8_t connFlags);

};



#endif
