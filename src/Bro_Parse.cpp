#include "Bro_Parse.h"
#include "diventi.h"
#include "Bro_Value.h"
#include "DiventiStream.h"

#include <vector>
#include <boost/algorithm/string.hpp>
#include <stdio.h>
#include <cstdlib>
#include <sstream>
#ifdef BRO_JSON
#include <ctime>
#endif

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
	BroEntry* be = static_cast<BroEntry*> (e);
	be->id_orig_p = strtol(s, nullptr, 10);
	return 0;
}

static int portRHandler(logEntry *e, char *s) {
	BroEntry* be = static_cast<BroEntry*> (e);
	be->id_resp_p = strtol(s, nullptr, 10);
	return 0;
}

static int hostOHandler(logEntry *e, char *s) {
	BroEntry* be = static_cast<BroEntry*> (e);
	inet_pton(AF_INET, s, &(be->id_orig_h));
	return 0;
}

static int hostRHandler(logEntry *e, char *s) {
	BroEntry* be = static_cast<BroEntry*> (e);
	inet_pton(AF_INET, s, &(be->id_resp_h));
	return 0;
}
#ifdef BRO_JSON
// 2019-11-06T23:59:53.184085Z
static int tsHandler(logEntry *e, char *s) {
	BroEntry* be = static_cast<BroEntry*> (e);
	if (s[0] != '-') {
		struct tm ctime;
		strptime(s, "%FT%T%z", &ctime);
		be->ts = mktime(&ctime)*1000000;	// Seconds
		be->ts += strtoll(s + 20, nullptr, 10); // Microseconds
		return 0;
	}
	be->ts=0;
	return -1;
}
#else
static int tsHandler(logEntry *e, char *s) {
	BroEntry* be = static_cast<BroEntry*> (e);
	if (s[0] != '-') {
		be->ts = strtoll(s, nullptr, 10)*1000000;	// Seconds
		be->ts += strtoll(s + 11, nullptr, 10); // Microseconds
		return 0;
	}
	be->ts=0;
	return -1;
}
#endif

static int protoHandler(logEntry *e, char *s) {
	BroEntry* be = static_cast<BroEntry*> (e);
	if (strncmp(s,"tcp",3)==0 || strncmp(s,"TCP",3)==0){ be->proto = TCP; }
	else if (strncmp(s,"udp",3)==0 || strncmp(s,"UDP",3)==0){ be->proto = UDP; }
	else if (strncmp(s,"icmp",4)==0 || strncmp(s,"ICMP",4)==0){ be->proto = ICMP; }
	else{ be->proto = UNKNOWN_TRANSPORT; }	// Covers unknown_transport and uncaught cases	
	return 0;
}

static int uidHandler(logEntry *e, char *s) {
	BroEntry* be = static_cast<BroEntry*> (e);
	int l = strlen(s);
	if(l>Bro_Value::BRO_UID_SIZE) {
		debug(25,"Warning: Uid not correct size \'%s\' is %d\n",s,l);
		l=Bro_Value::BRO_UID_SIZE;
	}
	memcpy(be->uid,s,l);
	if (l<Bro_Value::BRO_UID_SIZE)
		be->uid[l]=0;
	return 0;
}

static int durationHandler(logEntry *e, char *s) {
	BroEntry* be = static_cast<BroEntry*> (e);
	if (s[0] != '-'){
		be->duration = strtoll(s, nullptr, 10); 	// Seconds
		//duration += strtoll(next + 1, NULL, 10);	// Microseconds
		debug(90, "Parsed duration: %li\n", be->duration);
		return 0;
	}
	be->duration=-1;
	return -1;
}

static int origBytesHandler(logEntry *e, char *s) {
	BroEntry* be = static_cast<BroEntry*> (e);
	be->orig_bytes = strtoll(s, nullptr, 10);
	return 0;
}

static int respBytesHandler(logEntry *e, char *s) {
	BroEntry* be = static_cast<BroEntry*> (e);
	be->resp_bytes = strtoll(s, nullptr, 10);
	return 0;
}

static int connStateHandler(logEntry *e, char *s) {
	BroEntry* be = static_cast<BroEntry*> (e);
	be->conn_state = UNKNOWN_CONN;

	// NB: the order below is important to check 
	//     longest substring first.
	if (!strncmp(s,"S0",2)){ be->conn_state = S0; }
	else if (!strncmp(s,"S1",2)){ be->conn_state = S1; }
	else if (!strncmp(s,"SF",2)){ be->conn_state = SF; }
	else if (!strncmp(s,"REJ",3)){ be->conn_state = REJ; }
	else if (!strncmp(s,"S2",2)){ be->conn_state = S2; }
	else if (!strncmp(s,"S3",2)){ be->conn_state = S3; }
	else if (!strncmp(s,"RSTOS0",6)){ be->conn_state = RSTOS0; }
	else if (!strncmp(s,"RSTO",4)){ be->conn_state = RSTO; }
	else if (!strncmp(s,"RSTRH",5)){ be->conn_state = RSTRH; }
	else if (!strncmp(s,"SHR",3)){ be->conn_state = SHR; }
	else if (!strncmp(s,"SH",2)){ be->conn_state = SH; }
	else if (!strncmp(s,"OTH",3)){ be->conn_state = OTH; }	
	return 0;
}

static int origPackHandler(logEntry *e, char *s) {
	BroEntry* be = static_cast<BroEntry*> (e);
	be->orig_pkts = strtoll(s, nullptr, 10);
	return 0;
}

static int respPackHandler(logEntry *e, char *s) {
	BroEntry* be = static_cast<BroEntry*> (e);
	be->resp_pkts = strtoll(s, nullptr, 10);
	return 0;
}

//------------------------
#ifdef BRO_JSON
	// for json we ignore the fields argument
	BroFormat::BroFormat(std::string) {
		type[0] = TS;
		fieldHandler[0] = tsHandler;
		type[1] = UID;
		fieldHandler[1] = uidHandler;
		type[2] = ID_ORIG_H;
		fieldHandler[2] = hostOHandler;
		type[3] = ID_ORIG_P;
		fieldHandler[3]=portOHandler;
		type[4] = ID_RESP_H;
		fieldHandler[4]=hostRHandler;
		type[5] = ID_RESP_P;
		fieldHandler[5] = portRHandler;
		type[6] = PROTO;
		fieldHandler[6] = protoHandler;
		type[7] = DURATION;
		fieldHandler[7] = durationHandler;
		type[8] = ORIG_BYTES;
		fieldHandler[8] = origBytesHandler;
		type[9] = RESP_BYTES;
		fieldHandler[9] = respBytesHandler;
		type[10] = CONN_STATE;
		fieldHandler[10] = connStateHandler;
		type[11] = ORIG_PKTS;
		fieldHandler[11] = origPackHandler;
		type[12] = RESP_PKTS;
		fieldHandler[12] = respPackHandler;
		lastToken = 12;
	}
#else
	BroFormat::BroFormat(std::string fields) {
		for (int i = 0; i < MAX_FIELDS; i++){
			type[i] = UNUSED;
			fieldHandler[i]=nullptr;
		}
		if( fields == "" ) {
			diventi_error("ERROR: missing #fields or syslogArgs empty for bro-conn, specify in source description\n");
			exit(EXIT_FAILURE);
		}
		parse(fields);
	}
#endif

BroFormat::BroFormat(){
	for (int i = 0; i < MAX_FIELDS; i++){
		type[i] = UNUSED;
		fieldHandler[i]=nullptr;
	}
}

bool BroFormat::operator==(const logFormat& other){
	return !memcmp(type, dynamic_cast<const BroFormat &>(other).type, MAX_FIELDS * sizeof(logField));
}

BroFormat *BroFormat::operator=(const logFormat& other){
	for (int i = 0; i < MAX_FIELDS; i++){
		type[i] = dynamic_cast<const BroFormat &>(other).type[i];
	}
	return this;
}

std::string BroFormat::toString() const{
	std::stringstream str;
	str << "Log format:\n";
	for (int i = 0; i < MAX_FIELDS && type[i] != UNUSED; i++){
		str << i << ": " << fieldStr[type[i]] << "\n";
	}
	return str.str();
}

//Parsing functions for the header
//function that actually does the parsing of the header line
void BroFormat::parse(std::string fields){
	std::vector<std::string> toks;
	unsigned int i;
	debug(60, "parsing fields: %s\n", fields.c_str());

	boost::split(toks, fields, boost::is_any_of(std::string("\t ")), boost::token_compress_on);
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
		} else if (toks[i] == fieldStr[UID]){
			type[i] = UID;
			lastToken=i;
			fieldHandler[i] = uidHandler;
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
		} else if (toks[i] == fieldStr[SERVICE]){
			type[i] = SERVICE;
		} else if (toks[i] == fieldStr[DURATION]){
			type[i] = DURATION;
			lastToken=i;
			fieldHandler[i] = durationHandler;			
		} else if (toks[i] == fieldStr[ORIG_BYTES]){
			type[i] = ORIG_BYTES;
			lastToken=i;
			fieldHandler[i] = origBytesHandler;
		} else if (toks[i] == fieldStr[RESP_BYTES]){
			type[i] = RESP_BYTES;
			lastToken=i;
			fieldHandler[i] = respBytesHandler;
		} else if (toks[i] == fieldStr[CONN_STATE]){
			type[i] = CONN_STATE;
			lastToken=i;
			fieldHandler[i] = connStateHandler;
		}else if (toks[i] == fieldStr[LOCAL_ORIG]){
			type[i] = LOCAL_ORIG;
		} else if (toks[i] == fieldStr[LOCAL_RESP]){
			type[i] = LOCAL_RESP;
		} else if (toks[i] == fieldStr[MISSED_BYTES]){
			type[i] = MISSED_BYTES;
		} else if (toks[i] == fieldStr[HISTORY]){
			type[i] = HISTORY;
		} else if (toks[i] == fieldStr[ORIG_PKTS]){
			type[i] = ORIG_PKTS;
			lastToken=i;
			fieldHandler[i] = origPackHandler;
		} else if (toks[i] == fieldStr[ORIG_IP_BYTES]){
			type[i] = ORIG_IP_BYTES;
		} else if (toks[i] == fieldStr[RESP_PKTS]){
			type[i] = RESP_PKTS;
			lastToken=i;
			fieldHandler[i] = respPackHandler;
		} else if (toks[i] == fieldStr[RESP_IP_BYTES]){
			type[i] = RESP_IP_BYTES;
		} else if (toks[i] == fieldStr[TUNNEL_PARENTS]){
			type[i] = TUNNEL_PARENTS;
		} else if (toks[i] == fieldStr[ORIG_L2_ADDR]){
			type[i] = ORIG_L2_ADDR;
		} else if (toks[i] == fieldStr[RESP_L2_ADDR]){
			type[i] = RESP_L2_ADDR;
		} else if (toks[i] == fieldStr[VLAN]){
			type[i] = VLAN;
		} else if (toks[i] == fieldStr[INNER_VLAN]){
			type[i] = INNER_VLAN;
		} else{
			type[i] = UNKNOWN;
		}
		// debug(30, "Entry %d is of type '%s' (enum %d)\n", i, toks[i].c_str(), type[i]);
	}
        debug(45, "Fields Parsed lastToken:%d \n",lastToken);
	debug(75, "Fields: %s\n", toString().c_str());
}


//May be more efficient to do it this way constructor -> class's parse

// BroEntry::BroEntry(char *buf, int size, logFormat *fp){
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

BroEntry::BroEntry(){
	id_orig_h.s_addr = id_resp_h.s_addr = 0;
	ts = duration = -1;
	proto = EMPTY_PROTO;
	id_orig_p = id_resp_p = 0;
	orig_bytes = resp_bytes = orig_pkts = resp_pkts = 0;
	conn_state = UNKNOWN_CONN;
	uid[0] = 0;
}

BroEntry::~BroEntry(){
}

bool BroEntry::operator==( logEntry& oth){
	// Some fields not currently used
	BroEntry &other = dynamic_cast<BroEntry &>(oth);
	return (ts == other.ts) && (duration == other.duration)
		&& (strncmp(uid,other.uid,Bro_Value::BRO_UID_SIZE)==0) && (proto == other.proto)
	    /*&& (service == other.service)*/ 			&& (conn_state == other.conn_state)
	    //&& (history == other.history) 			&& (orig_l2_addr == other.orig_l2_addr)
	    /*&& (resp_l2_addr == other.resp_l2_addr)*/ && (id_orig_p == other.id_orig_p)
	    && (id_resp_p == other.id_resp_p) 		&& (orig_bytes == other.orig_bytes)
	    && (resp_bytes == other.resp_bytes) 	//&& (missed_bytes == other.missed_bytes) 
	    && (orig_pkts == other.orig_pkts) 		//&& (orig_ip_bytes == other.orig_ip_bytes) 
	    && (resp_pkts == other.resp_pkts) 		//&& (resp_ip_bytes == other.resp_ip_bytes) 
	    //&& (local_orig == other.local_orig) 	&& (local_resp == other.local_resp) 
	    //&& (vlan == other.vlan) 				&& (inner_vlan == other.inner_vlan)
	    && (id_orig_h.s_addr==other.id_orig_h.s_addr)
	    && (id_resp_h.s_addr==other.id_resp_h.s_addr)
	    //&& (tunnel_parents == other.tunnel_parents)
	    ;
}

BroEntry *BroEntry::operator=(const logEntry& oth){
	const BroEntry &other = dynamic_cast<const BroEntry &>(oth);
	ts = other.ts;
	duration = other.duration;
	memcpy(uid,other.uid,Bro_Value::BRO_UID_SIZE);
	proto = other.proto;
	service = other.service;
	conn_state = other.conn_state;
	history = other.history;
	orig_l2_addr = other.orig_l2_addr;
	resp_l2_addr = other.resp_l2_addr;
	id_orig_p = other.id_orig_p;
	id_resp_p = other.id_resp_p;
	orig_bytes = other.orig_bytes;
	resp_bytes = other.resp_bytes;
	missed_bytes = other.missed_bytes;
	orig_pkts = other.orig_pkts;
	orig_ip_bytes = other.orig_ip_bytes;
	resp_pkts = other.resp_pkts;
	resp_ip_bytes = other.resp_ip_bytes;
	local_orig = other.local_orig;
	local_resp = other.local_resp;
	vlan = other.vlan;
	inner_vlan = other.inner_vlan;
	tunnel_parents = other.tunnel_parents;
   
	id_orig_h.s_addr = other.id_orig_h.s_addr;
	id_resp_h.s_addr = other.id_resp_h.s_addr;
	return this;
}

std::string BroEntry::toString(){
	// Only the fields we care about
	std::stringstream str;
	str << "Log entry:\n";
	str << "ts: " << ts << "\n";
	str << "duration: " << duration << "\n";
	str << "uid: " << uid << "\n";
	str << "proto: " << protoStr[proto] << "\n";
	// str << "service: " << service << "\n";
	str << "conn_state: " << connStr[conn_state] << "\n";
	// str << "history: " << history << "\n";
	// str << "orig_l2_addr: " << orig_l2_addr << "\n";
	// str << "resp_l2_addr: " << resp_l2_addr << "\n";
	str << "id.orig_h: " << (inet_ntoa(id_orig_h)) << "\n";
	str << "id.orig_p: " << id_orig_p << "\n";
	str << "id.resp_h: " << (inet_ntoa(id_resp_h)) << "\n";
	str << "id.resp_p: " << id_resp_p << "\n";
	str << "orig_bytes: " << orig_bytes << "\n";
	str << "resp_bytes: " << resp_bytes << "\n";
	// str << "missed_bytes: " << missed_bytes << "\n";
	str << "orig_pkts: " << orig_pkts << "\n";
	// str << "orig_ip_bytes: " << orig_ip_bytes << "\n";
	str << "resp_pkts: " << resp_pkts << "\n";
	// str << "resp_ip_bytes: " << resp_ip_bytes << "\n";
	// str << "local_orig: " << local_orig << "\n";
	// str << "local_resp: " << local_resp << "\n";
	// str << "vlan: " << vlan << "\n";
	// str << "inner_vlan: " << inner_vlan << "\n";
	// str << "tunnel_parents: " << tunnel_parents << "\n";
	return str.str();
}
