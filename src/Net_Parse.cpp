#include "Net_Parse.h"
#include "diventi.h"
#include "Net_Value.h"
#include "DiventiStream.h"

#include <vector>
#include <boost/algorithm/string.hpp>
#include <stdio.h>
#include <cstdlib>
#include <sstream>

#include<iostream>

//------------------------------------
// Field handling routines used for parsing fields
//  These assume the first entry is a pointer to 
//  a log entry, the second is a null terminated string
//  they parse the field and insert it into e where appropriate
//
//  Returns an int.  
//    -1 == error
//    other values tbd.
//

static int portOHandler(logEntry *e, char *s) {
	NetEntry* ne = static_cast<NetEntry*> (e);
	ne->id_orig_p = strtol(s, nullptr, 10);
	return 0;
}

static int portRHandler(logEntry *e, char *s) {
	NetEntry* ne = static_cast<NetEntry*> (e);
	ne->id_resp_p = strtol(s, nullptr, 10);
	return 0;
}

static int hostOHandler(logEntry *e, char *s) {
	NetEntry* ne = static_cast<NetEntry*> (e);
	inet_pton(AF_INET, s, &(ne->id_orig_h));
	return 0;
}

static int hostRHandler(logEntry *e, char *s) {
	NetEntry* ne = static_cast<NetEntry*> (e);
	inet_pton(AF_INET, s, &(ne->id_resp_h));
	return 0;
}

// example timestamp 1535673547.040
static int tsHandler(logEntry *e, char *s) {
	NetEntry* ne = static_cast<NetEntry*> (e);
	if (s[0] != '-') {
		ne->ts = strtoll(s, nullptr, 10)*1000000;	// Seconds
		ne->ts += strtoll(s + 11, nullptr, 10)*1000; // Microseconds
		return 0;
	}
	ne->ts=0;
	return -1;
}

static int protoHandler(logEntry *e, char *s) {
	NetEntry* ne = static_cast<NetEntry*> (e);
	if (strncmp(s,"tcp",3)==0 || strncmp(s,"TCP",3)==0){ ne->proto = TCP; }
	else if (strncmp(s,"udp",3)==0 || strncmp(s,"UDP",3)==0){ ne->proto = UDP; }
	else if (strncmp(s,"icmp",4)==0 || strncmp(s,"ICMP",4)==0){ ne->proto = ICMP; }
	else{ ne->proto = UNKNOWN_TRANSPORT; }	// Covers unknown_transport and uncaught cases	
	return 0;
}

static int durationHandler(logEntry *e, char *s) {
	NetEntry* ne = static_cast<NetEntry*> (e);
	if (s[0] != '-'){
		ne->duration = strtoll(s, nullptr, 10); 	// Seconds
		//duration += strtoll(next + 1, NULL, 10);	// Microseconds
		debug(90, "Parsed duration: %li\n", ne->duration);
		return 0;
	}
	ne->duration=-1;
	return -1;
}

static int respBytesHandler(logEntry *e, char *s) {
	NetEntry* ne = static_cast<NetEntry*> (e);
	ne->bytes = strtoll(s, nullptr, 10);
	return 0;
}

static int tcpStateHandler(logEntry *e, char *s) {
	NetEntry* ne = static_cast<NetEntry*> (e);
	ne->tcp_flags = 0;
	if (s[0] == 'U'){ ne->tcp_flags |= 0x20; }
	if (s[1] == 'A'){ ne->tcp_flags |= 0x10; }
	if (s[2] == 'P'){ ne->tcp_flags |= 0x08; }
	if (s[3] == 'R'){ ne->tcp_flags |= 0x04; }
	if (s[4] == 'S'){ ne->tcp_flags |= 0x02; }
	if (s[5] == 'F'){ ne->tcp_flags |= 0x01; }
	return 0;
}

static int respPackHandler(logEntry *e, char *s) {
	NetEntry* ne = static_cast<NetEntry*> (e);
	ne->pkts = strtoll(s, nullptr, 10);
	return 0;
}

//------------------------

NetFormat::NetFormat(std::string fields) {
	for (int i = 0; i < MAX_FIELDS; i++){
		type[i] = UNUSED;
		fieldHandler[i]=nullptr;
	}
	if( fields == "" ) {
		perror("ERROR: missing #fields or syslogArgs empty for netAscii, specify in source description\n");
		exit(1);
	}
	parse(fields);
}

NetFormat::NetFormat(){
	for (int i = 0; i < MAX_FIELDS; i++){
		type[i] = UNUSED;
		fieldHandler[i]=nullptr;
	}
}

bool NetFormat::operator==(const logFormat& oth){
	const NetFormat &other = dynamic_cast<const NetFormat &>(oth);
	// debug(0, "other: %s", other.toString().c_str());
	return !memcmp(type, other.type, MAX_FIELDS * sizeof(logField));
}

NetFormat *NetFormat::operator=(const logFormat& other){
	for (int i = 0; i < MAX_FIELDS; i++){
		type[i] = dynamic_cast< const NetFormat &>(other).type[i];
	}
	return this;
}

std::string NetFormat::toString() const{
	std::stringstream str;
	str << "Log format:\n";
	for (int i = 0; i < MAX_FIELDS && type[i] != UNUSED; i++){
		str << i << ": " << fieldStr[type[i]] << "\n";
	}
	return str.str();
}

//parse the fields and set relevent functions
void NetFormat::parse(std::string fields){
	std::vector<std::string> toks;
	unsigned int i;
	boost::split(toks, fields,  boost::is_any_of(std::string("\t ")), boost::token_compress_on);

	// The first token should be #fields. Lets remove that.
   if (boost::iequals(toks[0],"#fields")) {
	   toks.erase(toks.begin());
   }

	/*
	 *   Process the fields line, building the handlers vector
	 *   and tracking the lastToken (aka the last token we need to process.
	 *
	 */
	lastToken=0;
	for (i = 0; i < toks.size(); i++){	
		if (toks[i] == fieldStr[TS]){
			type[i] = TS;
			lastToken=i;
			fieldHandler[i] = tsHandler;
		} else if (toks[i] == fieldStr[ID_ORIG_H]){
			type[i] = ID_ORIG_H;
			lastToken=i;
			fieldHandler[i] = hostOHandler;
		} else if (toks[i] == fieldStr[ID_ORIG_P]){
			type[i] = ID_ORIG_P;
			lastToken=i;
			fieldHandler[i]=portOHandler;
		} else if (toks[i] == fieldStr[ID_RESP_H]){
			type[i] = ID_RESP_H;
			lastToken=i;
			fieldHandler[i]=hostRHandler;
		} else if (toks[i] == fieldStr[ID_RESP_P]){
			type[i] = ID_RESP_P;
			lastToken=i;
			fieldHandler[i] = portRHandler;
		} else if (toks[i] == fieldStr[PROTO]){
			type[i] = PROTO;
			lastToken=i;
			fieldHandler[i] = protoHandler;
		} else if (toks[i] == fieldStr[DURATION]){
			type[i] = DURATION;
			lastToken=i;
			fieldHandler[i] = durationHandler;			
		} else if (toks[i] == fieldStr[BYTES]){
			type[i] = BYTES;
			lastToken=i;
			fieldHandler[i] = respBytesHandler;
		} else if (toks[i] == fieldStr[TCP_FLAG]){
			type[i] = TCP_FLAG;
			lastToken=i;
			fieldHandler[i] = tcpStateHandler;
		} else if (toks[i] == fieldStr[PKTS]){
			type[i] = PKTS;
			lastToken=i;
			fieldHandler[i] = respPackHandler;
		} else{
			type[i] = UNKNOWN;
		}
		debug(70, "Entry %d is of type '%s' (enum %d)\n", i, toks[i].c_str(), type[i]);
	}

	debug(55, "Fields Parsed lastToken:%d\n%s\n", lastToken, toString().c_str());
}

//May be more efficient to do it this way constructor -> class's parse
// NetEntry::NetEntry(char *buf, int size, logFormat *fp){
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

NetEntry::NetEntry(){
	id_orig_h.s_addr = id_resp_h.s_addr = 0;
	ts = duration = -1;
	proto = EMPTY_PROTO;
	id_orig_p = id_resp_p = 0;
	bytes = pkts = 0;
	tcp_flags = 0;
}

NetEntry::~NetEntry(){
}

bool NetEntry::operator==( logEntry& oth){
	NetEntry &other = dynamic_cast<NetEntry &>(oth);
	return (ts == other.ts) && (duration == other.duration)
		&& (proto == other.proto) && (tcp_flags == other.tcp_flags)
	    && (id_orig_p == other.id_orig_p) && (id_resp_p == other.id_resp_p)
		&& (bytes == other.bytes)
	    && (pkts == other.pkts)
	    && (id_orig_h.s_addr==other.id_orig_h.s_addr)
	    && (id_resp_h.s_addr==other.id_resp_h.s_addr);
}

NetEntry *NetEntry::operator=(const logEntry& oth){
	const NetEntry &other = dynamic_cast<const NetEntry &>(oth);
	ts = other.ts;
	duration = other.duration;
	proto = other.proto;
	tcp_flags = other.tcp_flags;
	id_orig_p = other.id_orig_p;
	id_resp_p = other.id_resp_p;
	bytes = other.bytes;
	pkts = other.pkts;
   
	id_orig_h.s_addr = other.id_orig_h.s_addr;
	id_resp_h.s_addr = other.id_resp_h.s_addr;
	return this;
}

std::string NetEntry::toString(){
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
