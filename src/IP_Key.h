#ifndef KEY_INCLUDED_DIVENTI
#define KEY_INCLUDED_DIVENTI

#include "diventi.h"

#include <tokudb.h>
#include <cstddef>

/*
	Stores key for diventi.
	Keys correspond to a pair of ips and ports and a time associated with a connection. 
*/

/* 
 *   A struct to define the raw data in the key.  This makes
 *   packing rather straight forward. 
 */

#ifndef IPV6
const static uint8_t IP_KEY_SIZE = 21;
#else
const static uint8_t IP_KEY_SIZE = 29;
#endif

typedef struct IP_rawKey {
#ifndef IPV6
	uint32_t ipA;
	uint32_t ipB;
#else
	uint64_t ipA;
	uint64_t ipB;
#endif
	uint64_t ts;
	uint16_t portA;
	uint16_t portB;
	uint8_t rev; //The reason why rev is a uint8 is that when keys are identical the records are lost
					//Making rev a number (odd if reversed) allows for more uniqueness
} IP_rawKey_t;




//  key data union kd_u
//    A union to format the key data in two ways.
union ip_kd_u {
	byte data[IP_KEY_SIZE];
	IP_rawKey_t key;
};

class IP_Key: public Key {
public:
	IP_Key(struct in_addr* id_orig_h, uint64_t ts, uint16_t id_orig_p, struct in_addr* id_resp_h, uint16_t id_resp_p, uint8_t reverse=0);
	IP_Key(DBT* dbt);
	IP_Key(byte* data);
	IP_Key(const IP_Key& key);
	IP_Key(const Key& key);
	~IP_Key();
	DBT *getDBT() const;
	struct in_addr* getOrigIP();
	uint64_t getTimestamp();
	char *getDate();
	uint16_t getOrigPort();
	struct in_addr* getRespIP();
	uint16_t getRespPort();
	bool isReversed();
	const char * timeStr();
	std::string ipOStr();
	std::string ipRStr();
	std::string toString();
	std::string toVerboseString();
	std::string toExtendedString();
	std::string toJsonString();

	IP_Key *operator=(const Key *other);
	bool operator==(const Key& other);
	bool operator!=(const Key& other);
	static const uint64_t timeoffset = 1000000;

	static Key *createFirstKey(std::map<std::string, std::string> &args);
	static Key *createLastKey(std::map<std::string, std::string> &args);

private:
	//DBT* dbt;
	DBT dbt;
	ip_kd_u keyData;
	void packData(struct in_addr* ipA, uint64_t timestamp,
		uint16_t portA, struct in_addr* ipB, uint16_t portB, uint8_t isReversed);
	struct in_addr* getIPA();
	struct in_addr* getIPB();
	uint16_t getPortA();
	uint16_t getPortB();

	const static int IPA_POS = 0;
#ifndef IPV6
	// if db will only hold v4 then optimize for space by reducing the amount of
	// space allocated for the ip address
	const static int TIMESTAMP_POS = IPA_POS + sizeof(uint32_t);
#else
	const static int TIMESTAMP_POS = IPA_POS + sizeof(uint64_t);
#endif
	const static int PORTA_POS = TIMESTAMP_POS + sizeof(int64_t);
	const static int IPB_POS = PORTA_POS + sizeof(int16_t);
	
#ifndef IPV6
	// if db will only hold v4 then optimize for space by reducing the amount of
	// space allocated for the ip address
	const static int PORTB_POS = IPB_POS + sizeof(uint32_t);
#else
	const static int PORTB_POS = IPB_POS + sizeof(uint64_t);
#endif
	const static int REV_POS = PORTB_POS + sizeof(int16_t);
	

	const static int KEY_MAX_CHAR_LENGTH = 2000; 
	const static int INIT_KEY_DATA_LEN = 64;

	const static int KEY_LEN2 = sizeof(IP_rawKey);
public:
	const static std::size_t KEY_SIZE = REV_POS + sizeof(uint8_t);
};

#endif
