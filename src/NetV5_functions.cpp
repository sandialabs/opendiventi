#include "NetV5_functions.h"
#include "diventi.h"
#include "IP_Key.h"
#include "Net_Value.h"
#include "KeyValuePair.h"
#include "DiventiStream.h"
#include "SyslogHandler.h"

#include <vector>
#include <boost/algorithm/string.hpp>
#include <stdio.h>
#include <cstdlib>
#include <sstream>

//globals for header variables
uint16_t version = 0;
uint16_t flowNum = 0;
uint64_t sysTime = 0;
uint64_t unixSec = 0;
uint64_t unix_NS = 0;
bool headerValid = true;

//global because we'll use it in multiple functions
uint64_t firstSysTime = 0;

//mutex for getSyslogData and getRawData as multiple threads will be using them
	//and they require shared resources
std::mutex mGet;

//-----------------------
//Functions for extracting data from the netflow header buffer
static void versionHandler(char *s) {
	uint16_t ver = 0;
	for( int j = 0; j < 2; j++ ) {
		ver += (uint8_t)s[VER+j] << (8*(1-j));
	}
	version = ver;
	debug(75, "version: %u\n", version);
	return;
}

static void countHandler(char *s) {
	uint16_t count = 0;
	for( int j = 0; j < 2; j++ ) {
		count += (uint8_t)s[COUNT+j] << (8*(1-j));
	}
	flowNum = count;
	debug(75, "flowNum set: %u\n", flowNum);
	return;
}

static void uptimeHandler(char *s) {
	uint64_t uptime = 0;
	for( int j = 0; j < 4; j++ ){
		uptime += (uint8_t)s[UPTIME+j] << (8*(3-j));
	}
	sysTime = uptime;
	debug(75, "sysTime set: %lu\n", sysTime);
	return;
}

static void unixSecsHandler(char *s) {
	uint64_t secs = 0;
	for( int j = 0; j < 4; j++ ){
		secs += (uint8_t)s[SECS+j] << (8*(3-j));
	}
	unixSec = secs;
	debug(75, "unixSec set: %lu\n", unixSec);
	return;
}

static void nanoSecsHandler(char *s) {
	uint64_t nsecs = 0;
	for( int j = 0; j < 4; j++ ){
		nsecs += (uint8_t)s[NSECS+j] << (8*(3-j));
	}
	unix_NS = nsecs;
	debug(75, "NanoSec set: %lu\n", unix_NS);
	return;
}

//-----------------------
//Fuctions for extracting data from the netflow data buffer
static int TimeHandler(logEntry *e, char *s) {
	NetEntry* ne = static_cast<NetEntry*> (e);
	firstSysTime = 0;
	for( int j = 0; j < 4; j++ ){
		firstSysTime += (uint8_t)s[FIRST+j] << (8*(3-j));
	}
	// Conversion so that ne->ts is in microseconds
	ne->ts = unixSec*1e6 + (unix_NS*.001) + (firstSysTime*1000);
	debug(75, "sec:%lu, ns: %lu, first: %lu, result: %lu\n", unixSec, unix_NS, firstSysTime, ne->ts);
	return 0;
}

static int OIPHandler(logEntry *e, char *s) {
	NetEntry* ne = static_cast<NetEntry*> (e);
	uint32_t ip = 0;
	for( int j = 0; j < 4; j++ ){
		ip += (uint8_t)s[SRC_IP+j] << (8*(3-j));
	}
	ne->id_orig_h.s_addr = htonl(ip); //printing expects network order
	return 0;
}

static int OPortHandler(logEntry *e, char *s) {
	NetEntry* ne = static_cast<NetEntry*> (e);
	uint16_t port = 0;
	for( int j = 0; j < 2; j++ ) {
		port += (uint8_t)s[SRC_PORT+j] << (8*(1-j));
	}
	ne->id_orig_p = port;
	return 0;
}

static int RIPHandler(logEntry *e, char *s) {
	NetEntry* ne = static_cast<NetEntry*> (e);
	uint32_t ip = 0;
	for( int j = 0; j < 4; j++ ){
		ip += (uint8_t)s[DST_IP+j] << (8*(3-j));
	}
	ne->id_resp_h.s_addr = htonl(ip); //printing expects network order
	return 0;
}

static int RPortHandler(logEntry *e, char *s) {
	NetEntry* ne = static_cast<NetEntry*> (e);
	uint16_t port = 0;
	for( int j = 0; j < 2; j++ ) {
		port += (uint8_t)s[DST_PORT+j] << (8*(1-j));
	}
	ne->id_resp_p = port;
	return 0;
}

static int ProtoHandler(logEntry *e, char *s) {
	NetEntry* ne = static_cast<NetEntry*> (e);
	uint8_t prot = (uint8_t)s[PROT];
	if (prot == 0) { 		ne->proto = EMPTY_PROTO; } 
	else if (prot == 1) { 	ne->proto = ICMP; } 
	else if (prot == 6) { 	ne->proto = TCP; } 
	else if (prot == 17){ 	ne->proto = UDP; } 
	else { 					ne->proto = UNKNOWN_TRANSPORT; }

	return 0;
}

static int DurHandler(logEntry *e, char *s) {
	NetEntry* ne = static_cast<NetEntry*> (e);
	//get last time
	uint64_t lastTime = 0;
	for( int j = 0; j < 4; j++ ){
		lastTime += (uint8_t)s[LAST+j] << (8*(3-j));
	}
	ne->duration = (lastTime - firstSysTime)*.001;
	return 0;
}

static int BytesHandler(logEntry *e, char *s) {
	NetEntry* ne = static_cast<NetEntry*> (e);
	uint32_t byte = 0;
	for( int j = 0; j < 4; j++ ){
		byte += (uint8_t)s[BYT+j] << (8*(3-j));
	}
	ne->bytes = byte;
	return 0;
}

static int FlagsHandler(logEntry *e, char *s) {
	NetEntry* ne = static_cast<NetEntry*> (e);
	ne->tcp_flags = (uint8_t)s[FLAGS];
	return 0;
}

static int PktsHandler(logEntry *e, char *s) {
	NetEntry* ne = static_cast<NetEntry*> (e);
	uint32_t pkts = 0;
	for( int j = 0; j < 4; j++ ){
		pkts += (uint8_t)s[PKT+j] << (8*(3-j));
	}
	ne->pkts = pkts;
	return 0;
}


//------------------------------------


bool NetV5::parseFileFormat(std::string /*file*/, logFormat **format) {
	debug(60, "identified netflow\n");
	std::string line;
	*format = createFormat(line);
	return true;
}

//Function to parse NetV5 buffers (public)
int NetV5::parseBuf(char * buf, int size, logFormat **f, std::list<logEntry *> *results){
	NetFormat *fp = dynamic_cast<NetFormat *>(*f);
	int entries = size/48;
	debug(70, "size = %d, entries = %d\n", size, entries*2);
	for(int j = 0; j < entries; j++) {
		NetEntry *e = new NetEntry();
		for (int i = 0; i < fp->lastToken; i++) {
			(*(fp->fieldHandler[i]))(e,buf+(48*j));
		}
		//debug(0, "Inserted logEntry: %s", e->toString().c_str());
		results->push_back(e);
	}
	return entries*2;
}

KeyValuePair *NetV5::createPair(uint8_t index, std::list<logEntry*> *results, uint8_t source) {
	debug(80, "current size of results: %lu, index = %d", results->size(), index);
	NetEntry e;
	e = *results->front();
	if( index % 2 != 0 ) {
		delete results->front();
		results->pop_front();
	}

	//create the key using index as a marker of whether the key should be reversed
	//the first key will have index of 0 so false and next will be one so true (repeat as needed)
	IP_Key *key = new IP_Key(&(e.id_orig_h), e.ts , e.id_orig_p, 
			&(e.id_resp_h), e.id_resp_p, index);
	Net_Value *value = new Net_Value(source, e.proto, e.duration,
			e.bytes, e.tcp_flags, e.pkts);
	KeyValuePair *pair = new KeyValuePair(*key, *value);
	return pair;
}

//------------------------------
//function which uses diventiStream to read a line from the conn.log
int NetV5::getRawData(char * buf, DiventiStream *stream) {
	mGet.lock();
	int size = stream->getBytes(buf, 24);
	debug(80, "size of read: %d\n", size);
	if(size == 24) {
		debug(75, "handling a header\n");
		versionHandler(buf);
		if(version != 5)
			printf("Unexpected netflow version %u ... data may be corrupted\n", version);
		countHandler(buf);
		uptimeHandler(buf);
		unixSecsHandler(buf);
		nanoSecsHandler(buf);
	}
	debug(65, "handling %u flows.\n", flowNum);
	int numBytes = flowNum*48;
	flowNum = 0;
	//Tell stream to read 48*flownum bytes
	size = stream->getBytes(buf, numBytes);
	mGet.unlock();
	return size;
}

/*
Just some notes and code for v9
VER = 0
COUNT = 2
UPTIME = 4
SECS = 8
NSECS = 12
(package sequence is 4 bytes)
(Source ID 4 bytes)

Flow ID = 0 (if zero then defining a templete, if not then referencing a templete and using a data flow)

*/
//Function to read bytes from the udp buffer
unsigned int NetV5::getSyslogData(SyslogHandler *slh, char * buf, logFormat **fp) {
	//function to read bytes already well established
	//just call it feeding the number of bytes to read
	mGet.lock();
	OPTIONS.syslogOffset = 0;
	int size = slh->getNextBytes(buf, 24, fp);
	debug(70, "size of syslog read: %d\n", size);
	flowNum = 0;
	if(size == 24) {
		debug(75, "handling a header\n");
		versionHandler(buf);
		if(version != 5)
			printf("Unexpected netflow version %u \t data may be corrupted\n", version);
		countHandler(buf);
		uptimeHandler(buf);
		unixSecsHandler(buf);
		nanoSecsHandler(buf);
	}
	debug(65, "handling %u flows.\n", flowNum);
	int numBytes = flowNum*48;
	//Tell stream to read 48*flownum bytes
	size = slh->getNextBytes(buf, numBytes, fp);
	mGet.unlock();
	return size;
}

Key *NetV5::createKey(DBT *dbt) {
	IP_Key *key = new IP_Key(dbt);
	return key;
}

Value *NetV5::createValue(DBT *dbt) {
	Net_Value *value = new Net_Value(dbt);
	return value;
}

std::string NetV5::getHeader() {
	return "ts           orig_ip   orig_port   resp_ip     resp_port    proto   duration   bytes  tcp_flags  packets";
}

/*
 * Retrieves the key for a file. The key is the first non-empty, non-comment line.
 * If no such lines exist, returns the file name.
 */
std::string NetV5::getKey(std::string fileName){
	//mapping from nibbles to hex characters
	constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

	char buf[24];
	// Open the file
	DiventiStream ds(fileName);
	// If there are no more lines to get and no valid line has been found
	if (!ds.good()){
		debug(15, "WARNING: using filename %s for key\n", fileName.c_str());
		return fileName;
	}

	// In this case we want to read the header(24 bytes) as that should unique
	int size = ds.getBytes(buf, 24);

	if (size == 0) {
		debug(5, "WARNING: Failed to grab key from netflow v5 file: %s, using default key\n", fileName.c_str());
		// return a default key
		return std::string(47, '0').append("1");
	}

	std::string ret(48, ' '); //initialize the return value with 48 spaces
	//preform buf value to hex conversion
	for(int i = 0; i < 24; i++) {
		ret[i*2]     = hexmap[(buf[i] & 0xF0) >> 4]; // convert first nibble
		ret[i*2 + 1] = hexmap[buf[i] & 0x0F];      // convert second nibble
	}
	return ret;
}

logFormat *NetV5::createFormat(std::string /*fields*/) {
	NetFormat *form = new NetFormat();
	//the fields are constant for v5
	form->fieldHandler[0] = TimeHandler;
	form->fieldHandler[1] = OIPHandler;
	form->fieldHandler[2] = OPortHandler;
	form->fieldHandler[3] = RIPHandler;
	form->fieldHandler[4] = RPortHandler;
	form->fieldHandler[5] = ProtoHandler;
	form->fieldHandler[6] = DurHandler;
	form->fieldHandler[7] = BytesHandler;
	form->fieldHandler[8] = FlagsHandler;
	form->fieldHandler[9] = PktsHandler;
	form->lastToken = 10;
	debug(60, "Fields Parsed lastToken:%d\n%s\n", form->lastToken, form->toString().c_str());
	return form;
}

std::string NetV5::getStats() {
	//will eventually want to put counts of dropped packets and such things here
	return "";
}
