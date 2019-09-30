#include "IP_Key.h"
#include "diventi.h"

#include <tokudb.h>
#include <endian.h>
#include <ctime>
#include <time.h>
#include <climits>

/*
	The key is the timestamp of the log, the ip addresses, and the ports used
*/


IP_Key::IP_Key(struct in_addr* id_orig_h, uint64_t ts, uint16_t id_orig_p, 
	struct in_addr* id_resp_h, uint16_t id_resp_p, uint8_t reverse){

	dbt.data = &keyData;
	if (reverse % 2 != 0){ //reverse is true when it is odd
		packData(id_resp_h, ts, id_resp_p, id_orig_h, id_orig_p, reverse);
	} else{
		packData(id_orig_h, ts, id_orig_p, id_resp_h, id_resp_p, reverse);
	}
	//dbt.flags |= DB_DBT_MALLOC;
	dbt.flags =0;
	dbt.size = KEY_SIZE;
	dbt.ulen = KEY_SIZE;
	KEY_BYTES = KEY_LEN2;
}

IP_Key::IP_Key(DBT* d) {
	dbt.data = &keyData;	
	memcpy(this->dbt.data, d->data, d->size);
	this->dbt.flags = d->flags;
	this->dbt.size = d->size;
	this->dbt.ulen = d->ulen;
	KEY_BYTES = KEY_LEN2;
}

IP_Key::IP_Key(byte* data) {
	dbt.data = &keyData;
	memcpy(dbt.data, data, KEY_SIZE);
	//dbt.flags |= DB_DBT_MALLOC;
	dbt.flags =0;
	dbt.size = KEY_SIZE;
	dbt.ulen = KEY_SIZE;
	KEY_BYTES = KEY_LEN2;
}

IP_Key::IP_Key(const IP_Key& key){
	dbt.data = &keyData;
	memcpy(dbt.data, key.getDBT()->data, KEY_SIZE);
	//dbt.flags |= DB_DBT_MALLOC;
	dbt.flags =0;
	dbt.size = KEY_SIZE;
	dbt.ulen = KEY_SIZE;
	KEY_BYTES = KEY_LEN2;
}

IP_Key::IP_Key(const Key& key){
	dbt.data = &keyData;
	memcpy(dbt.data, dynamic_cast<const IP_Key &>(key).getDBT()->data, KEY_SIZE);
	//dbt.flags |= DB_DBT_MALLOC;
	dbt.flags =0;
	dbt.size = KEY_SIZE;
	dbt.ulen = KEY_SIZE;
	KEY_BYTES = KEY_LEN2;
}

IP_Key::~IP_Key() {
}

IP_Key *IP_Key::operator=(const Key *other){
	memcpy(dbt.data, other->getDBT()->data, KEY_SIZE);
	//dbt.flags |= DB_DBT_MALLOC;
	dbt.flags =0;
	dbt.size = KEY_SIZE;
	dbt.ulen = KEY_SIZE;
	KEY_BYTES = KEY_SIZE;
	return this;
}

DBT* IP_Key::getDBT() const{
	return (DBT*) &dbt;
}

bool IP_Key::operator==(const Key& other) {
	return !memcmp(dbt.data, other.getDBT()->data, KEY_SIZE);
}

bool IP_Key::operator!=(const Key& other) {
	return !(*this == other);
}

// int64_t Key::getTimestamp() {
// 	return *((int64_t*) ((byte*)dbt->data + TIMESTAMP_POS));
// }

uint64_t IP_Key::getTimestamp() {
	return be64toh(*((uint64_t*) ((byte*)dbt.data + TIMESTAMP_POS)));
}

char * IP_Key::getDate() {
	char *buf = new char();
	time_t time = (time_t)(getTimestamp()/timeoffset);
	struct tm *timestruct;
	timestruct = localtime(&time);
	strftime(buf, 20, "%R %D", timestruct);
	return buf;
}

struct in_addr* IP_Key::getOrigIP(){
	return isReversed() ? getIPB() : getIPA();
}

struct in_addr* IP_Key::getRespIP(){
	return isReversed() ? getIPA() : getIPB();
}

uint16_t IP_Key::getOrigPort(){
	return isReversed() ? getPortB() : getPortA();
}

uint16_t IP_Key::getRespPort(){
	return isReversed() ? getPortA() : getPortB();
}

bool IP_Key::isReversed(){
	return *((uint8_t*) ((byte*)dbt.data + REV_POS)) % 2 != 0;
}

struct in_addr* IP_Key::getIPA() {
	struct in_addr* ret = new struct in_addr();
	ret->s_addr = be32toh(htonl(*((unsigned long*) ((byte*)dbt.data + IPA_POS))));
	return ret;
}

uint16_t IP_Key::getPortA() {
	return be16toh(*((uint16_t*) ((byte*)dbt.data + PORTA_POS)));
}

struct in_addr* IP_Key::getIPB() {
	struct in_addr* ret = new struct in_addr();
	ret->s_addr = be32toh(htonl(*((unsigned long*) ((byte*)dbt.data + IPB_POS))));
	return ret;
}

uint16_t IP_Key::getPortB() {
	return be16toh(*((uint16_t*) ((byte*)dbt.data + PORTB_POS)));
}

/*
ts			orig_ip				orig_port	resp_ip				resp_port
981927378	120.116.196.204		2208		216.190.159.150		80
981927378	120.116.196.204		2208		216.190.159.150		80
ts			orig_ip				orig_port	resp_ip				resp_port
Received 2 entries.
*/

std::string IP_Key::toString() {	
	// Extract IPs
	char cstrIPO[INET_ADDRSTRLEN];
	char cstrIPR[INET_ADDRSTRLEN];
	struct in_addr* ipO = getOrigIP();
	struct in_addr* ipR = getRespIP();
	inet_ntop(AF_INET, ipO, cstrIPO, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, ipR, cstrIPR, INET_ADDRSTRLEN);

	//fill in char array
	char retCharArr[KEY_MAX_CHAR_LENGTH];
	uint64_t ts = getTimestamp();
	int charsToBeWritten = sprintf(retCharArr, 
		"%-17s   %-15s   %-9u   %-15s   %-9u",	// ts, orig ip, orig port, resp ip, resp port
		(ts != (uint64_t)-1) ? (std::to_string(ts/timeoffset) + "." + std::to_string(ts%timeoffset)).c_str() : "-",
		cstrIPO,
		getOrigPort(),
		cstrIPR,
		getRespPort()
	);

	std::string ret = std::string(retCharArr);

	if(charsToBeWritten >= KEY_MAX_CHAR_LENGTH) {
		ret = ret.substr(0, KEY_MAX_CHAR_LENGTH-5) + std::string("...\n\n");
	}

	delete ipO;
	delete ipR;

	return ret;
}

std::string IP_Key::toVerboseString() {
	// Extract IPs
	char cstrIPO[INET_ADDRSTRLEN];
	char cstrIPR[INET_ADDRSTRLEN];
	struct in_addr* ipO = getOrigIP();
	struct in_addr* ipR = getRespIP();
	inet_ntop(AF_INET, ipO, cstrIPO, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, ipR, cstrIPR, INET_ADDRSTRLEN);

	//fill in char array
	char retCharArr[KEY_MAX_CHAR_LENGTH];
	char *date = getDate();
	int charsToBeWritten = sprintf(retCharArr, 
		"%-17s   %-15s   %-9u   %-15s   %-9u",	// ts, orig ip, orig port, resp ip, resp port
		date,
		cstrIPO,
		getOrigPort(),
		cstrIPR,
		getRespPort()
	);

	std::string ret = std::string(retCharArr);

	if(charsToBeWritten >= KEY_MAX_CHAR_LENGTH) {
		ret = ret.substr(0, KEY_MAX_CHAR_LENGTH-5) + std::string("...\n\n");
	}

	delete ipO;
	delete ipR;
	delete date;

	return ret;
}

std::string IP_Key::toExtendedString() {
	// Extract IPs
	char cstrIPO[INET_ADDRSTRLEN];
	char cstrIPR[INET_ADDRSTRLEN];
	struct in_addr* ipO = getOrigIP();
	struct in_addr* ipR = getRespIP();
	inet_ntop(AF_INET, ipO, cstrIPO, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, ipR, cstrIPR, INET_ADDRSTRLEN);

	//fill in char array
	char retCharArr[KEY_MAX_CHAR_LENGTH];
	uint64_t ts = getTimestamp();
	int charsToBeWritten = sprintf(retCharArr, 
		"\ttimestamp: %s\n"
		"\tid.orig_h: %s\n"
		"\tid.orig_p: %u\n"
		"\tid.resp_h: %s\n"
		"\tid.resp_p: %u\n",
		(ts != (uint64_t)-1) ? (std::to_string(ts/timeoffset) + "." + std::to_string(ts%timeoffset)).c_str() : "-",
		cstrIPO,
		getOrigPort(),
		cstrIPR,
		getRespPort()
	);

	std::string ret = std::string(retCharArr);

	if(charsToBeWritten >= KEY_MAX_CHAR_LENGTH) {
		ret = ret.substr(0, KEY_MAX_CHAR_LENGTH-5) + std::string("...\n\n");
	}

	delete ipO;
	delete ipR;

	return ret;
}

/*
	Evan - 06/23
	Function to return a json formatted key string
	Idea is for this function to return a key object
	This object is then made up of many name/value pairs
	Each of these corresponds to a element of the key

	updated for new architecture 07/27/18
*/
std::string IP_Key::toJsonString() {
	// Extract IPs
	char cstrIPO[INET_ADDRSTRLEN];
	char cstrIPR[INET_ADDRSTRLEN];
	struct in_addr* ipO = getOrigIP();
	struct in_addr* ipR = getRespIP();
	inet_ntop(AF_INET, ipO, cstrIPO, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, ipR, cstrIPR, INET_ADDRSTRLEN);

	//fill in char array
	char retCharArr[KEY_MAX_CHAR_LENGTH];
	uint64_t ts = getTimestamp();
	int charsToBeWritten = sprintf(retCharArr, 
		"\"timestamp\": \"%s\","
		"\"id.orig_h\": \"%s\","
		"\"id.orig_p\": %u,"
		"\"id.resp_h\": \"%s\","
		"\"id.resp_p\": %u",
		(ts != (uint64_t)-1) ? (std::to_string(ts/timeoffset) + "." + std::to_string(ts%timeoffset)).c_str() : "-",
		cstrIPO,
		getOrigPort(),
		cstrIPR,
		getRespPort()
	);

	std::string ret = std::string(retCharArr);

	//if the output is too big... shorten it
	if(charsToBeWritten >= KEY_MAX_CHAR_LENGTH) {
		ret = ret.substr(0, KEY_MAX_CHAR_LENGTH-5) + std::string("...\n\n");
	}

	delete ipO;
	delete ipR;

	return ret;
}

/*
	Function to return binary representation of the data
		ewest - updated 07/26/18
*/
uint8_t *IP_Key::toBinary() {
	//Convert to binary and apply host to network conversions
	uint8_t *x;
	x = new uint8_t[KEY_BYTES]{0};
	uint64_t time = getTimestamp();
	time = htobe64(time);
	x[0] = time >> 56;
	x[1] = (time & 0xFF000000000000) >> 48;
	x[2] = (time & 0xFF0000000000) >> 40;
	x[3] = (time & 0xFF00000000) >> 32;
	x[4] = (time & 0xFF000000) >> 24;
	x[5] = (time & 0xFF0000) >> 16;
	x[6] = (time & 0xFF00) >> 8;
	x[7] = (time & 0xFF);
	uint32_t orig = (uint32_t)getOrigIP()->s_addr;
	orig = htonl(orig);
	x[8] = orig >> 24;
	x[9] = (orig & 0x00FF0000) >> 16;
	x[10] = (orig & 0x0000FF00) >> 8;
	x[11] = (orig & 0x000000FF);
	uint16_t oport = getOrigPort();
	oport = htons(oport);
	x[12] = oport >> 8;
	x[13] = oport & 0x000000FF;
	uint32_t resp = (uint32_t)getRespIP()->s_addr;
	resp = htonl(resp);
	x[14] = resp >> 24;
	x[15] = (resp & 0x00FF0000) >> 16;
	x[16] = (resp & 0x0000FF00) >> 8;
	x[17] = (resp & 0x000000FF);
	uint16_t rport = getRespPort();
	rport = htons(rport);
	x[18] = rport >> 8;
	x[19] = rport & 0x000000FF;
	return x;
}

/*
 *  Does same as binPack w/o alloc
 *    Takes the data elements and packs them into the 
 *    Keys' data without all the allocating of the predecessor.
 */
void IP_Key::packData(struct in_addr* ipA, uint64_t timestamp,
	uint16_t portA, struct in_addr* ipB, uint16_t portB, uint8_t reversed) {
	if(ipA == nullptr || ipB == nullptr) {
		throw std::invalid_argument("A null pointer was provided in one of the IPs.");
	}

#if 0
	// TODO -- fix assignments using union. -- data is not in same format... 
	// All members must be in big endian for keyCompare to work	
	keyData.key.ipA  =   htobe32(ntohl(ipA->s_addr));	
	keyData.key.ts =  htobe32(timestamp);
	keyData.key.portA =  htobe16(portA);
	keyData.key.ipB = htobe32(ntohl(ipB->s_addr));
	keyData.key.portB = htobe16(portB);
	keyData.key.rev =  reversed;
#endif

	unsigned long aAddr, bAddr;
	byte *ret;
	ret = keyData.data;

	// All members must be in big endian for keyCompare to work     
	aAddr = htobe32(ntohl(ipA->s_addr));    
	memcpy(ret + IPA_POS, &aAddr, sizeof(unsigned long));
	
	timestamp = htobe64(timestamp);
	memcpy(ret + TIMESTAMP_POS, &timestamp, sizeof(uint64_t));
	
	portA = htobe16(portA);
	memcpy(ret + PORTA_POS, &portA, sizeof(uint16_t));
	
	bAddr = htobe32(ntohl(ipB->s_addr));
	memcpy(ret + IPB_POS, &bAddr, sizeof(unsigned long));
	
	portB = htobe16(portB);
	memcpy(ret + PORTB_POS, &portB, sizeof(uint16_t));
	
	memcpy(ret + REV_POS, &reversed, sizeof(uint8_t)); // Big endian does not matter with 1 flag
}

//Returns the argument in a string->string map specified by name "ip"
static struct in_addr firstIP(std::map<std::string, std::string> &args){
	struct in_addr ip;
	inet_pton(AF_INET, args["ip"].c_str(), &ip);
	return ip;
}

//Returns either the same thing that firstIP returned or returns the lastIP
static struct in_addr lastIP(std::map<std::string, std::string> &args){
	struct in_addr ip;
	if (args.count("range") == 0){
		inet_pton(AF_INET, args["ip"].c_str(), &ip);
	} else{
		inet_pton(AF_INET, args["range"].c_str(), &ip);
	}
	return ip;
}

//This function sets the start time if provided in the args. If not it's set to zero
static uint64_t startTime(std::map<std::string, std::string> &args){
	if (args.count("startTime") == 0){
		return 0;
	} else{
		return std::stoul(args["startTime"]);
	}
}

//Sets endTime in the same fashion as start time but end of time if UDF
static uint64_t endTime(std::map<std::string, std::string> &args){
	if (args.count("endTime") == 0){
		return ~0;	// End of time
	} else{
		return std::stoul(args["endTime"]);
	}
}

//ZZ TODO - do we actually need seperate functions for these operations?

//Function that parses the url arguments and returns the Key which denotes the
//	first valid index
Key *IP_Key::createFirstKey(std::map<std::string, std::string> &args) {
	struct in_addr zeroIP;
	struct in_addr ipStart = firstIP(args);
	inet_pton(AF_INET, "0.0.0.0", &zeroIP);
	IP_Key *startKey = new IP_Key(&ipStart, startTime(args), 0, &zeroIP, 0);
	return startKey;
}

//Function that creates the last valid index and returns it
Key *IP_Key::createLastKey(std::map<std::string, std::string> &args) {
	struct in_addr maxIP;
	struct in_addr ipEnd = lastIP(args);
	inet_pton(AF_INET, "255.255.255.255", &maxIP);
	IP_Key *endKey = new IP_Key(&maxIP, endTime(args), USHRT_MAX, &ipEnd, USHRT_MAX, 1);
	return endKey;
}