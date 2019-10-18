#include "Mon_Parse.h"
#include "diventi.h"
#include "Mon_Value.h"
#include "DiventiStream.h"

#include <vector>
#include <boost/algorithm/string.hpp>
#include <stdio.h>
#include <cstdlib>
#include <sstream>
#include <time.h>

//------------------------------------
// Field handling routines used for parsing fields
//  These assume the first entry is a pointer to l
//  a log entry, the second is a null terminated string
//  they parse the field and insert it into e where appropriate
//
//  Returns an int.  
//    -1 == error
//    other values tbd.
//

static int portOHandler(logEntry *e, char *s) {
        MonEntry* me = static_cast<MonEntry*> (e);
	me->id_orig_p = strtol(s, nullptr, 10);
	return 0;
}

static int portRHandler(logEntry *e, char *s) {
        MonEntry* me = static_cast<MonEntry*> (e);
	me->id_resp_p = strtol(s, nullptr, 10);
	return 0;
}

static int hostOHandler(logEntry *e, char *s) {
        MonEntry* me = static_cast<MonEntry*> (e);
	inet_pton(AF_INET, s, &(me->id_orig_h));
	return 0;
}

static int hostRHandler(logEntry *e, char *s) {
        MonEntry* me = static_cast<MonEntry*> (e);
	inet_pton(AF_INET, s, &(me->id_resp_h));
	return 0;
}

static int tsHandler(logEntry *e, char *s) {
        MonEntry* me = static_cast<MonEntry*> (e);
        struct tm tm;
        time_t t;
        char * end;
        end = strptime(s,"%Y-%m-%dT%H:%M:%S",&tm);
        if ((end - s) < 16) {
                debug(43,"Error parsing time stamp %s\n",s);
                return -1;
        }
        t = mktime(&tm);
        me->ts = t * 1000000;	// Seconds
        return 0;
}


static int durationHandler(logEntry *e, char *s) {
        MonEntry* me = static_cast<MonEntry*> (e);
        me->duration = strtoll(s, nullptr, 10); 	// Seconds
        return 0;
}

static int origBytesHandler(logEntry *e, char *s) {
        MonEntry* me = static_cast<MonEntry*> (e);
	me->orig_bytes = strtoll(s, nullptr, 10);
	return 0;
}

static int respBytesHandler(logEntry *e, char *s) {
        MonEntry* me = static_cast<MonEntry*> (e);
	me->resp_bytes = strtoll(s, nullptr, 10);
	return 0;
}

// Connection flags have the following format for tcp
//    6 slots with dots when not sent or with a designated letter.
//   e.g.  ......  SsADFR or any combination e.g.  SsAD.. or .....R
//  we use a bit to represent each slot.
static int connFlagsHandler(logEntry *e, char *s) {
        MonEntry* me = static_cast<MonEntry*> (e);
        me->connFlags=0;
        for (int i=0; i< Mon_Value::num_flags; i++) {
                if (s[i]!='.') 
                        // turn on the i-th bit of the connFlags
                        me->connFlags |= (0x01 << i);
        }
        return 0;
}


//------------------------


// MonFormat::MonFormat(){
// }

MonFormat::MonFormat(transProto p){
        mon_proto = p;

        // Statically define the handlers for each field.
        //  2019-01-01T18:10:14-Tue 0 10.12.41.5 -> 10.2.0.2 39640 => 80 SsADF. 603 +> 1648
        //  
        fieldHandler[0] = tsHandler;

        if (p==ICMP) {
                // Set up values for ICMP and return
                fieldHandler[1] = hostOHandler;
                fieldHandler[2] = nullptr;
                fieldHandler[3] = hostRHandler;
        
                fieldHandler[4] = origBytesHandler;
                lastToken=4;
                return;
        }

        fieldHandler[1] = durationHandler;

        fieldHandler[2] = hostOHandler;
        fieldHandler[3] = nullptr;
        fieldHandler[4] = hostRHandler;
        
        fieldHandler[5] = portOHandler;
        fieldHandler[6] = nullptr; 
        fieldHandler[7] = portRHandler;

        if (p==UDP) {
                // Set up if UDP or ICMP
                fieldHandler[8] = origBytesHandler;
                lastToken=8;
                return;
        }

        // OK we're TCP finish up the TCP fields.
        fieldHandler[8] = connFlagsHandler;
        
        fieldHandler[9] = origBytesHandler;
        fieldHandler[10] = nullptr;
        fieldHandler[11] = respBytesHandler;
        lastToken=11;

}

bool MonFormat::operator==(const logFormat& other){
        for (int i=0; i<= lastToken; i++) {
                if (fieldHandler[i]!=dynamic_cast<const MonFormat &>(other).fieldHandler[i]) 
                        return false;
        }

        return true;
}

MonFormat *MonFormat::operator=(const logFormat& other){
        lastToken = dynamic_cast<const MonFormat &>(other).lastToken;
        mon_proto = dynamic_cast<const MonFormat &>(other).mon_proto;
        
        for (int i=0; i<= lastToken; i++) 
                fieldHandler[i]=dynamic_cast<const MonFormat &>(other).fieldHandler[i];

	return this;
}

std::string MonFormat::toString() const{
	std::stringstream str;
	str << "Log format:\n";
        str << "Mon parsing of TCP logs\n";
	return str.str();
}


// Constructor for an entry.  We set values to default empties.
MonEntry::MonEntry(){
	id_orig_h.s_addr = id_resp_h.s_addr = 0;
	ts = duration = -1;
	proto = EMPTY_PROTO; 
	id_orig_p = id_resp_p = 0;
	orig_bytes = resp_bytes = 0;
	connFlags = 0;
}

MonEntry::~MonEntry(){
}

bool MonEntry::operator==( logEntry& oth){       
	MonEntry &other = dynamic_cast<MonEntry &>(oth);
	return (ts == other.ts) && (duration == other.duration)
                && (id_orig_h.s_addr==other.id_orig_h.s_addr)
                && (id_resp_h.s_addr==other.id_resp_h.s_addr)
                && (id_orig_p == other.id_orig_p)  && (id_resp_p == other.id_resp_p)
                && (orig_bytes == other.orig_bytes) && (resp_bytes == other.resp_bytes)
		&& (connFlags == other.connFlags) && (proto == other.proto);
}

MonEntry *MonEntry::operator=(const logEntry& oth){
	const MonEntry &other = dynamic_cast<const MonEntry &>(oth);
	ts = other.ts;
	duration = other.duration;
	proto = other.proto;
	connFlags = other.connFlags;
	id_orig_h.s_addr = other.id_orig_h.s_addr;
	id_resp_h.s_addr = other.id_resp_h.s_addr;
	id_orig_p = other.id_orig_p;
	id_resp_p = other.id_resp_p;
	orig_bytes = other.orig_bytes;
	resp_bytes = other.resp_bytes;
	local_orig = other.local_orig;
	local_resp = other.local_resp;
   	return this;
}

std::string MonEntry::connFlagtoString() {
        std::stringstream s;       
        for (int i =0; i< Mon_Value::num_flags; i++) {
                if (connFlags & (0x1 << i))                         
                        s<< Mon_Value::flagStr[i];
                else
                        s<< ".";
        }
        return s.str();
}

// Produce a string from this entry
std::string MonEntry::toString(){

	// Only the fields we care about
	std::stringstream str;
	str << "Log entry:\n";
	str << "ts: " << ts << "\n";
	str << "duration: " << duration << "\n";
	str << "proto: " << protoStr[proto] << "\n";
        str << "connFlags: " << connFlagtoString() << "\n";

	str << "id.orig_h: " << (inet_ntoa(id_orig_h)) << "\n";
	str << "id.orig_p: " << id_orig_p << "\n";
	str << "id.resp_h: " << (inet_ntoa(id_resp_h)) << "\n";
	str << "id.resp_p: " << id_resp_p << "\n";
	str << "orig_bytes: " << orig_bytes << "\n";
	str << "resp_bytes: " << resp_bytes << "\n";
	return str.str();
}
