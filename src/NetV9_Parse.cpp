#include "NetV9_Parse.h"
#include "diventi.h"
#include "DiventiStream.h"

#include <vector>
#include <boost/algorithm/string.hpp>
#include <stdio.h>
#include <cstdlib>
#include <sstream>



std::string  const NetV9_Format::fieldStr[] = {"ts", "id.orig_h", "id.orig_p",
					"id.resp_h", "id.resp_p", "proto",
					"duration", "bytes", "tcp_flags",
					"pkts", "UNUSED", "UNKNOWN"};

                                         
// uint64_t beginTime = 0;

//-----------------------
// Fuctions for extracting data from the netflow data buffer
int TimeHandler(logEntry *e, char *c) {
	NetV9_Entry* ie = static_cast<NetV9_Entry*> (e);
	uint8_t *s = reinterpret_cast<uint8_t *> (c);
	uint64_t beginTime = 0;
	for( int j = 0; j < 8; j++ ){
		beginTime += (uint64_t)s[j] << (8*(7-j));
	}
	//Multiply SysTime (seconds) times 100 to get it in microseconds
	ie->ts = beginTime*1000;
	debug(60, "time: %lu\n", ie->ts);
	return 0;
}


int DurHandler(logEntry *e, char *c) {
	NetV9_Entry* ie = static_cast<NetV9_Entry*> (e);
	uint8_t *s = reinterpret_cast<uint8_t *> (c);
	//get last time
	uint64_t lastTime = 0;
	for( int j = 0; j < 8; j++ ){
		lastTime += (uint64_t)s[j] << (8*(7-j));
	}
	
	// Multiply by .0000001 to convert to seconds
	ie->duration = (lastTime*1000 - ie->ts)*.000001;
	debug(60, "first: %lu, last: %lu, duration: %lu\n", ie->ts, lastTime, ie->duration);
	return 0;
}

int OIPHandler(logEntry *e, char *c) {
	NetV9_Entry* ie = static_cast<NetV9_Entry*> (e);
	uint8_t *s = reinterpret_cast<uint8_t *> (c);
	uint32_t ip = 0;
	for( int j = 0; j < 4; j++ ){
		ip += s[j] << (8*(3-j));
	}
	ie->id_orig_h.s_addr = htonl(ip); //printing expects network order
	debug(60, "ip: %u\n", ip);
	return 0;
}

int OPortHandler(logEntry *e, char *c) {
	NetV9_Entry* ie = static_cast<NetV9_Entry*> (e);
	uint8_t *s = reinterpret_cast<uint8_t *> (c);
	uint16_t port = 0;
	for( int j = 0; j < 2; j++ ) {
		port += s[j] << (8*(1-j));
	}
	ie->id_orig_p = port;
	debug(60, "port: %u\n",ie->id_orig_p);
	return 0;
}

int RIPHandler(logEntry *e, char *c) {
	NetV9_Entry* ie = static_cast<NetV9_Entry*> (e);
	uint8_t *s = reinterpret_cast<uint8_t *> (c);
	uint32_t ip = 0;
	for( int j = 0; j < 4; j++ ){
		ip += s[j] << (8*(3-j));
	}
	ie->id_resp_h.s_addr = htonl(ip); //printing expects network order
	debug(60, "ipR: %u\n", ip);
	return 0;
}

int RPortHandler(logEntry *e, char *c) {
	NetV9_Entry* ie = static_cast<NetV9_Entry*> (e);
	uint8_t *s = reinterpret_cast<uint8_t *> (c);        
	uint16_t port = 0;
	for( int j = 0; j < 2; j++ ) {
		port += s[j] << (8*(1-j));
	}
	ie->id_resp_p = port;
	debug(60, "portR: %u\n",ie->id_orig_p);
	return 0;
}

int ProtoHandler(logEntry *e, char *c) {
	NetV9_Entry* ie = static_cast<NetV9_Entry*> (e);
	uint8_t *s = reinterpret_cast<uint8_t *> (c);
	uint8_t prot = s[0];
	if (prot == 0) { 		ie->proto = EMPTY_PROTO; } 
	else if (prot == 1) { 	ie->proto = ICMP; } 
	else if (prot == 6) { 	ie->proto = TCP; } 
	else if (prot == 17){ 	ie->proto = UDP; } 
	else { 					ie->proto = UNKNOWN_TRANSPORT; }
	debug(60, "proto: %u\n",ie->proto);
	return 0;
}

int BytesHandler(logEntry *e, char *c) {
	NetV9_Entry* ie = static_cast<NetV9_Entry*> (e);
	uint8_t *s = reinterpret_cast<uint8_t *> (c);
	uint32_t byte = 0;
	for( int j = 0; j < 8; j++ ){
		byte += (uint64_t)s[j] << (8*(7-j));
	}
	ie->bytes = byte;
	debug(60, "bytes: %lu\n",ie->bytes);
	return 0;
}

int FlagsHandler(logEntry *e, char *c) {
	NetV9_Entry* ie = static_cast<NetV9_Entry*> (e);
	uint8_t *s = reinterpret_cast<uint8_t *> (c);
	ie->tcp_flags = s[0];
	debug(60, "bytes: %u\n",ie->tcp_flags);
	return 0;
}

int PktsHandler(logEntry *e, char *c) {
	NetV9_Entry* ie = static_cast<NetV9_Entry*> (e);        
	uint8_t *s = reinterpret_cast<uint8_t *> (c);
	uint32_t pkts = 0;
	for( int j = 0; j < 8; j++ ){
		pkts += (uint64_t)s[j] << (8*(7-j));
	}
	debug(60, "packets: %lu\n",ie->pkts);
	ie->pkts = pkts;
	return 0;
}

//------------------------

NetV9_Format::NetV9_Format(uint8_t *buf, uint16_t *length) {
	for (int i = 0; i < MAX_FIELDS; i++){
		type[i] = UNUSED;
		fieldHandler[i]=nullptr;
	}
	*length = parseTemplate(buf);
}

NetV9_Format::NetV9_Format(){
	for (int i = 0; i < MAX_FIELDS; i++){
		type[i] = UNUSED;
		fieldHandler[i]=nullptr;
	}
}

bool NetV9_Format::operator==(const logFormat& other){
	return !memcmp(type, dynamic_cast<const NetV9_Format &>(other).type, MAX_FIELDS * sizeof(logField));
}

NetV9_Format &NetV9_Format::operator=(const logFormat& oth){
	const NetV9_Format &other = dynamic_cast<const NetV9_Format &>(oth);
	for (int i = 0; i < MAX_FIELDS; i++){
		type[i] = other.type[i];
		locations[i] = other.locations[i];
	}
	totalSize = other.totalSize;
	return *this;
}

std::string NetV9_Format::toString() const{
	std::stringstream str;
	str << "Log format:\n";
	for (int i = 0; i < MAX_FIELDS && type[i] != UNUSED; i++){
		str << i << ": " << fieldStr[type[i]] << " location: " << locations[i] << "\n";
	}
	str << "totalSize: " << totalSize << "\n";
	return str.str();
}

//parse the template and create a NetV9_Format that corresponds
uint16_t NetV9_Format::parseTemplate(uint8_t *s){
	//Calculate the length of the template
	lastToken=0;
	uint16_t count = (s[F_COUNT] << 8) + s[F_COUNT + 1];

	uint skipped = 0;
	uint16_t pos = 0;
	for(uint field = 0; field < count; field++ ) {
		uint position = (field << 2) + 4;
		uint16_t name = (s[position] << 8) + s[position + 1];
		uint16_t size = (s[position+2] << 8) + s[position+3];
		totalSize += size;
		if(field - skipped >= MAX_FIELDS) {
			debug(10, "error in parsing template, too many relevant fields. Stopping now\n");
			return count << 2;
		}
		switch(name) {
			case BYTS: fieldHandler[field - skipped] = BytesHandler;
					debug(62, "fieldHandler[%i] = Bytes\n", field-skipped);
					locations[field - skipped] = pos;
					debug(62, "locations[%i] = %u\n", field-skipped, pos);
					type[field - skipped] = BYTES;
					pos += size;
					lastToken += 1;
					break;
			case PKTES: fieldHandler[field - skipped] = PktsHandler;
					debug(62, "fieldHandler[%i] = Pkts\n", field-skipped);
					locations[field - skipped] = pos;
					debug(62, "locations[%i] = %u\n", field-skipped, pos);
					type[field - skipped] = PKTS;
					pos += size;
					lastToken += 1;
					break;
			case PROTOCOL: fieldHandler[field - skipped] = ProtoHandler;
					debug(62, "fieldHandler[%i] = Proto\n", field-skipped);
					locations[field - skipped] = pos;
					debug(62, "locations[%i] = %u\n", field-skipped, pos);
					type[field - skipped] = PROTO;
					pos += size;
					lastToken += 1;
					break;
			case TCP_FLAGS: fieldHandler[field - skipped] = FlagsHandler;
					debug(62, "fieldHandler[%i] = Flags\n", field-skipped);
					locations[field - skipped] = pos;
					debug(62, "locations[%i] = %u\n", field-skipped, pos);
					type[field - skipped] = TCP_FLAG;
					pos += size;
					lastToken += 1;
					break;
			case SRC_PORT: fieldHandler[field - skipped] = OPortHandler;
					debug(62, "fieldHandler[%i] = OPort\n", field-skipped);
					locations[field - skipped] = pos;
					debug(62, "locations[%i] = %u\n", field-skipped, pos);
					type[field - skipped] = ID_ORIG_P;
					pos += size;
					lastToken += 1;
					break;
			case SRC_IP: fieldHandler[field - skipped] = OIPHandler;
					debug(62, "fieldHandler[%i] = OIP\n", field-skipped);
					locations[field - skipped] = pos;
					debug(62, "locations[%i] = %u\n", field-skipped, pos);
					type[field - skipped] = ID_ORIG_H;
					pos += size;
					lastToken += 1;
					break;
			case DST_PORT: fieldHandler[field - skipped] = RPortHandler;
					debug(62, "fieldHandler[%i] = RPort\n", field-skipped);
					locations[field - skipped] = pos;
					debug(62, "locations[%i] = %u\n", field-skipped, pos);
					type[field - skipped] = ID_RESP_P;
					pos += size;
					lastToken += 1;
					break;
			case DST_IP: fieldHandler[field - skipped] = RIPHandler;
					debug(62, "fieldHandler[%i] = RIP\n", field-skipped);
					locations[field - skipped] = pos;
					debug(62, "locations[%i] = %u\n", field-skipped, pos);
					type[field - skipped] = ID_RESP_H;
					pos += size;
					lastToken += 1;
					break;
			case START_M: fieldHandler[field - skipped] = TimeHandler;
					debug(62, "fieldHandler[%i] = Time\n", field-skipped);
					locations[field - skipped] = pos;
					debug(62, "locations[%i] = %u\n", field-skipped, pos);
					type[field - skipped] = TS;
					pos += size;
					lastToken += 1;
					break;
			case END_M: fieldHandler[field - skipped] = DurHandler;
					debug(62, "fieldHandler[%i] = Dur\n", field-skipped);
					locations[field - skipped] = pos;
					debug(62, "locations[%i] = %u\n", field-skipped, pos);
					type[field - skipped] = DURATION;
					pos += size;
					lastToken += 1;
					break;
			default: skipped += 1;
					pos += size;
					break;
		}
	}
	debug(62, "totalSize: %u, number of fields: %u\n", totalSize, lastToken);
	debug(62, "END of template\n\n");
	return count << 2;
}

//May be more efficient to do it this way constructor -> class's parse
// NetV9_Entry::NetV9_Entry(char *buf, int size, logFormat *fp){
// 	// Initialize all fields we care about - can have some serious problems otherwise
// 	id_orig_h.s_addr = id_resp_h.s_addr = 0;
// 	ts = duration = -1;
// 	proto = EMPTY_PROTO;
// 	id_orig_p = id_resp_p = 0;
// 	orig_bytes = resp_bytes = orig_pkts = resp_pkts = 0;
// 	uid[0] = 0;
// 	uid[1] = '\0'; //if it's netflow it will stay, if bro will be overwritten
// 	//now call the parsing function on the buffer that was defined by parseAndInsert() (insertThread)
// 	functions->parseBuf(buf, size, fp, this);
// }

NetV9_Entry::NetV9_Entry(){
	id_orig_h.s_addr = id_resp_h.s_addr = 0;
	ts = duration = -1;
	proto = EMPTY_PROTO;
	id_orig_p = id_resp_p = 0;
	bytes = pkts = 0;
	tcp_flags = 0;
}

NetV9_Entry::NetV9_Entry( const logEntry &other) 
        : NetV9_Entry(dynamic_cast<NetV9_Entry const &>(other))
{}

NetV9_Entry::~NetV9_Entry(){
}

bool NetV9_Entry::operator==( logEntry& oth){
	// Some fields not currently used
	NetV9_Entry &other = dynamic_cast<NetV9_Entry &>(oth);
	return (ts == other.ts) && (duration == other.duration)
		&& (proto == other.proto)
	    && (id_orig_p == other.id_orig_p)
	    && (id_resp_p == other.id_resp_p) 		
	    && (bytes == other.bytes)
	    && (pkts == other.pkts) 
	    && (id_orig_h.s_addr==other.id_orig_h.s_addr)
	    && (id_resp_h.s_addr==other.id_resp_h.s_addr);
}

std::string NetV9_Entry::toString(){
	std::stringstream str;
	str << "Log entry:\n";
	str << "ts: " << ts << "\n";
	str << "duration: " << duration << "\n";
	str << "proto: " << protoStr[proto] << "\n";
	str << "tcp_flags: " << tcp_flags << "\n";
	str << "id.orig_h: " << (inet_ntoa(id_orig_h)) << "\n";
	str << "id.orig_p: " << id_orig_p << "\n";
	str << "id.resp_h: " << (inet_ntoa(id_resp_h)) << "\n";
	str << "id.resp_p: " << id_resp_p << "\n";
	str << "bytes: " << bytes << "\n";
	str << "pkts: " << pkts << "\n";
	return str.str();
}
