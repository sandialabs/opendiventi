
#include "diventi.h"
#include "Mon_Value.h"

#include <sstream>

#include <tokudb.h>

/*
	The value is the parts of the log that don't include the ips, ports, or timestamp
	includes: protocol, duration, bytes transfered and recieved, and so on
*/



std::string const  Mon_Value::flagStr[] = {"S", "s", "A", "D", "F", "R"};



//   static here specifies that these functions are scoped to inside this file only.
//     --could these be put into a header file or the base class for value?
//
static inline int log2(uint64_t val){
	val += 1; // Round up by up to 1 - avoids undefined 0 case and differentiates 1 from 0
	asm("bsr %[val], %[val]"
			: [val] "+r" (val)
			:
			: "cc");
	return val;
}

static inline std::string mag_to_str(int magnitude){
	if (magnitude == 0){
		return "0";
	} else{
		return "[" + std::to_string((1 << magnitude) - 1) + " - " + 
				std::to_string((1 << (magnitude + 1)) - 1) + ")";
	}
}


std::string Mon_Value::connFlagtoString(uint8_t flags) {
        std::stringstream s;   
        for (int i=0; i<= num_flags; i++) {
                if (flags & (1 << i))                         
                        s<< flagStr[i];
                else
                        s<< ".";
        }
        return s.str();
}


Mon_Value::Mon_Value(uint8_t source, transProto protocol, uint32_t duration, int originBytes,
	int respBytes, uint8_t connFlags) {
	dbt.data = & vData;
	packData(source, protocol, duration, originBytes,
			 respBytes, connFlags);
	dbt.flags=0;
	dbt.size = VALUE_SIZE;
	dbt.ulen = VALUE_SIZE;
}

Mon_Value::Mon_Value(DBT* d) {
	dbt.data = & vData;

	memcpy(dbt.data, d->data, d->size);
	dbt.flags = d->flags;
	dbt.size = d->size;
	dbt.ulen = d->ulen;
}

Mon_Value::Mon_Value(byte* data) {
	dbt.data = & vData;

	memcpy(dbt.data, data, VALUE_SIZE);
	//dbt.flags |= DB_DBT_MALLOC;
	dbt.flags =0;
	dbt.size = VALUE_SIZE;
	dbt.ulen = VALUE_SIZE;
}

Mon_Value::Mon_Value(const Mon_Value& v){
	dbt.data = & vData;

	memcpy(dbt.data, v.getDBT()->data, VALUE_SIZE);
	//dbt.flags |= DB_DBT_MALLOC;
	dbt.flags =0;
	dbt.size = VALUE_SIZE;
	dbt.ulen = VALUE_SIZE;
}

Mon_Value::Mon_Value(const Value& v){
	dbt.data = & vData;

	memcpy(dbt.data, dynamic_cast<const Mon_Value &>(v).getDBT()->data, VALUE_SIZE);
	dbt.flags =0;
	dbt.size = VALUE_SIZE;
	dbt.ulen = VALUE_SIZE;
}

Mon_Value::~Mon_Value() {
}

DBT* Mon_Value::getDBT() const{
	return (DBT*) &dbt;
}

Mon_Value *Mon_Value::operator=(const Value *other){
	memcpy(dbt.data, other->getDBT()->data, VALUE_SIZE);
	dbt.flags |= DB_DBT_MALLOC;
	dbt.size = VALUE_SIZE;
	dbt.ulen = VALUE_SIZE;
	return this;
}

bool Mon_Value::operator==(const Value& other) {
	return (memcmp(dbt.data, other.getDBT()->data, dbt.size) == 0);
}

bool Mon_Value::operator!=(const Value& other) {
	return !(*this == other);
}

std::string Mon_Value::getTag() {
	uint8_t src = (uint8_t) ((char *)dbt.data)[0];
	return OPTIONS.sources[src]->tag;
}

transProto Mon_Value::getProtocol() {
	return (transProto)(*((uint8_t*) ((byte*)dbt.data + PROTO_POS)) );
}

uint32_t Mon_Value::getDuration() {
	return *((uint32_t*) ((byte*)dbt.data + DURATION_POS));
}

uint8_t Mon_Value::getOrigBytes() {
	return *((uint8_t*) ((byte*)dbt.data + ORIGIN_BYTES_POS));
}

uint8_t Mon_Value::getRespBytes() {
	return *((uint8_t*) ((byte*)dbt.data + RESP_BYTES_POS));
}

uint8_t Mon_Value::getConnFlags() {
	return  (uint8_t)(*((uint8_t*) ((byte*)dbt.data + FLAGS_POS)) );	
}


/*
proto	duration	orig_bytes	resp_bytes	conn_flags
tcp	1     	       	[1,3)	       	0		SsAD..

*/

std::string Mon_Value::toString() {
	uint32_t duration = getDuration();
	std::string state;
	char retCharArr[VAL_MAX_CHAR_LENGTH];

	// Setup strings that may chance because
	// of protocol
	transProto p = getProtocol();
    
	std::string flags="-";
	std::string oBytes="-";
	std::string rBytes="-";
            
	if (p==TCP) {
		oBytes = mag_to_str(getOrigBytes());
		rBytes = mag_to_str(getRespBytes()).c_str();
		flags = connFlagtoString(getConnFlags());
    }
	else if (p==UDP || p==ICMP) {
		oBytes = mag_to_str(getOrigBytes());
	}
                
	//fill in char array
    int charsToBeWritten = sprintf(retCharArr,
		"%-12s   %-5s   %-8s   %-17s  %-17s  %-9s   %-10s  %-10s  %18s",	// source tag, protocol, duration, orig bytes, resp bytes, conn state, orig packts, resp packets, uid
		getTag().c_str(),
		protoStr[getProtocol()].c_str(),
		(duration != (uint32_t)-1) ? std::to_string(duration).c_str() : "-",
		oBytes.c_str(), rBytes.c_str(), flags.c_str(),
		"-", "-", "-                   " // Mon doesn't have pkts or uid
	);

	std::string ret = std::string(retCharArr);

	if(charsToBeWritten >= VAL_MAX_CHAR_LENGTH) {
		ret = ret.substr(0, VAL_MAX_CHAR_LENGTH-5) + std::string("...\n\n");
	}
	return ret;
}

std::string Mon_Value::toVerboseString() {
	return toString();
}

std::string Mon_Value::toExtendedString() {

	uint32_t duration = getDuration();

	//fill in char array
	char retCharArr[VAL_MAX_CHAR_LENGTH];
	int charsToBeWritten =
		sprintf(retCharArr,
		"\ttag: %s\n"
		"\tprotocol: %s\n"
		"\tduration: %s\n"
		"\torigin bytes: %s\n"
		"\tresp_bytes: %s\n"
		"\tconn flags: %s\n",
		getTag().c_str(),
		protoStr[getProtocol()].c_str(),
		(duration != (uint32_t)-1) ? std::to_string(duration).c_str() : "-",
		mag_to_str(getOrigBytes()).c_str(),
		mag_to_str(getRespBytes()).c_str(),
		connFlagtoString(getConnFlags()).c_str()
		);
	std::string ret = std::string(retCharArr);

	if(charsToBeWritten >= VAL_MAX_CHAR_LENGTH) {
		ret = ret.substr(0, VAL_MAX_CHAR_LENGTH-5) + std::string("...\n\n");
	}

	return ret;
}

/*
	Function to return a json formatted value string
	Which contains json objects that correspond to value fields
		ewest - 06/23/18
*/
std::string Mon_Value::toJsonString() {
	uint32_t duration = getDuration();

	//fill in char array
	char retCharArr[VAL_MAX_CHAR_LENGTH];
	int charsToBeWritten = sprintf(retCharArr,
		"\"tag\": \"%s\","
		"\"protocol\": \"%s\","
		"\"duration\": \"%s\","
		"\"origin_bytes\": \"%s\","
		"\"resp_bytes\": \"%s\","
		"\"conn_flags\": \"%s\",",
		getTag().c_str(),
		protoStr[getProtocol()].c_str(),
		(duration != (uint32_t)-1) ? std::to_string(duration).c_str() : "-",
		mag_to_str(getOrigBytes()).c_str(),
		mag_to_str(getRespBytes()).c_str(),
		connFlagtoString(getConnFlags()).c_str()
		);
	std::string ret = std::string(retCharArr);

	if(charsToBeWritten >= VAL_MAX_CHAR_LENGTH) {
		ret = ret.substr(0, VAL_MAX_CHAR_LENGTH-5) + std::string("...\n\n");
	}
	return ret;
}

/*
 *  Packs the data without calling alloc etc.
 */
void Mon_Value::packData(uint8_t src, transProto protocol, uint32_t duration,
                         int originBytes, int respBytes, uint8_t connFlags) {

	uint8_t magnitude;
	uint8_t source = src;
	std::memcpy(vData + SOURCE_POS, &source, sizeof(uint8_t));
        
	std::memcpy(vData + PROTO_POS, &protocol, sizeof(uint8_t));
	std::memcpy(vData + DURATION_POS, &duration, sizeof(uint32_t));

	magnitude = log2(originBytes);	// Convert to magnitude
	debug(90, "originBytes: %d -> %s\n", magnitude, mag_to_str(magnitude).c_str());
	std::memcpy(vData + ORIGIN_BYTES_POS, &magnitude, sizeof(uint8_t));

	magnitude = log2(respBytes);	// Convert to magnitude
	debug(90, "respBytes: %d -> %s\n", magnitude, mag_to_str(magnitude).c_str());
	std::memcpy(vData + RESP_BYTES_POS, &magnitude, sizeof(uint8_t));

	std::memcpy(vData + FLAGS_POS, &connFlags, sizeof(uint8_t));
}
