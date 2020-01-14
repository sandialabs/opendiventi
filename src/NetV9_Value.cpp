#include "NetV9_Value.h"
#include "diventi.h"

#include <sstream>
#include <tokudb.h>

/*
	The value is the parts of the log that don't include the ips, ports, or timestamp
	includes: protocol, duration, bytes transfered and recieved, and so on
*/

std::string const  NetV9_Value::flagStr[] = {"U", "A", "P", "R", "S", "F"};

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

NetV9_Value::NetV9_Value(uint8_t source, transProto protocol, uint32_t duration, int bytes,
		uint8_t flags, int packets) {
	dbt.data = & vData;
	packData(source, protocol, duration, bytes,
			 flags, packets);
	//dbt.flags |= DB_DBT_MALLOC;
	dbt.flags=0;
	dbt.size = VALUE_SIZE;
	dbt.ulen = VALUE_SIZE;
}

NetV9_Value::NetV9_Value(DBT* d) {
	dbt.data = & vData;

	memcpy(dbt.data, d->data, d->size);
	dbt.flags = d->flags;
	dbt.size = d->size;
	dbt.ulen = d->ulen;
}

NetV9_Value::NetV9_Value(byte* data) {
	dbt.data = & vData;

	memcpy(dbt.data, data, VALUE_SIZE);
	//dbt.flags |= DB_DBT_MALLOC;
	dbt.flags =0;
	dbt.size = VALUE_SIZE;
	dbt.ulen = VALUE_SIZE;
}

NetV9_Value::NetV9_Value(const NetV9_Value& v){
	dbt.data = & vData;

	memcpy(dbt.data, v.getDBT()->data, VALUE_SIZE);
	//dbt.flags |= DB_DBT_MALLOC;
	dbt.flags =0;
	dbt.size = VALUE_SIZE;
	dbt.ulen = VALUE_SIZE;
}

NetV9_Value::NetV9_Value(const Value& v){
	dbt.data = & vData;

	memcpy(dbt.data, dynamic_cast<const NetV9_Value &>(v).getDBT()->data, VALUE_SIZE);
	//dbt.flags |= DB_DBT_MALLOC;
	dbt.flags =0;
	dbt.size = VALUE_SIZE;
	dbt.ulen = VALUE_SIZE;
}

NetV9_Value::~NetV9_Value() {
}

DBT* NetV9_Value::getDBT() const{
	return (DBT*) &dbt;
}

NetV9_Value *NetV9_Value::operator=(const Value *other){
	memcpy(dbt.data, other->getDBT()->data, VALUE_SIZE);
	dbt.flags |= DB_DBT_MALLOC;
	dbt.size = VALUE_SIZE;
	dbt.ulen = VALUE_SIZE;
	return this;
}

bool NetV9_Value::operator==(const Value& other) {
	return (memcmp(dbt.data, other.getDBT()->data, dbt.size) == 0);
}

std::string NetV9_Value::getTag() {
	uint8_t src = (uint8_t) ((char *)dbt.data)[0];
	return OPTIONS.sources[src]->tag;
}

transProto NetV9_Value::getProtocol() {
	return (transProto)(*((uint8_t*) ((byte*)dbt.data + PROTO_POS)) & 0xf);	// Lowest 4 bits
}

uint32_t NetV9_Value::getDuration() {
	return *((uint32_t*) ((byte*)dbt.data + DURATION_POS));
	// return 0;
}

uint8_t NetV9_Value::getBytes() {
	return *((uint8_t*) ((byte*)dbt.data + BYTES_POS));
}

uint8_t NetV9_Value::getTcpFlags() {
	return *((uint8_t*) ((byte*)dbt.data + TCP_POS));
}

uint8_t NetV9_Value::getPkts() {
	return *((uint8_t*) ((byte*)dbt.data + PKTS_POS));
}


std::string NetV9_Value::tcpStr() {
	std::stringstream s;
	uint8_t flags = getTcpFlags();
	for (int i=0; i<= num_flags; i++) {
		if (flags & (1 << i))                         
			s<< flagStr[i];
		else
			s<< ".";
	}
	debug(70, "flags: %s\n", s.str().c_str());
	return s.str();
}

/*
proto				duration	orig_bytes	resp_bytes	conn_state	orig_pkts	resp_pkts
tcp					-			0			0			RSTRH		0			[1, 3)	
icmp				-			0			0			RSTRH		0			[1, 3)	
proto				duration	orig_bytes	resp_bytes	conn_state	orig_pkts	resp_pkts
*/

std::string NetV9_Value::toString() {
	uint32_t duration = getDuration();

	//fill in char array
	char retCharArr[VAL_MAX_CHAR_LENGTH];
	int charsToBeWritten;
	charsToBeWritten = sprintf(retCharArr,
		"%-12s   %-5s   %-8s   %-17s  %-17s  %-9s   %-10s  %-10s  %18s",	// source tag, protocol, duration, orig bytes, resp bytes, conn state, orig packts, resp packets, uid
		getTag().c_str(),
		protoStr[getProtocol()].c_str(),
		(duration != (uint32_t)-1) ? std::to_string(duration).c_str() : "-",
		mag_to_str(getBytes()).c_str(),
		"-", //NetV9 doesn't have response bytes
		tcpStr().c_str(),
		mag_to_str(getPkts()).c_str(),
		"-", //NetV9 doesn't have response pkts
		"-                   " // NetV9 doesn't have uid
	);
	
	std::string ret = std::string(retCharArr);

	if(charsToBeWritten >= VAL_MAX_CHAR_LENGTH) {
		ret = ret.substr(0, VAL_MAX_CHAR_LENGTH-5) + std::string("...\n\n");
	}

	return ret;
}

std::string NetV9_Value::toVerboseString() {
	return toString();
}

std::string NetV9_Value::toExtendedString() {
	uint32_t duration = getDuration();
	//fill in char array
	char retCharArr[VAL_MAX_CHAR_LENGTH];
	int charsToBeWritten = sprintf(retCharArr,
		"\ttag: %s\n"
		"\tprotocol: %s\n"
		"\tduration: %s\n"
		"\tbytes: %s\n"
		"\ttcp_flags: %s\n"
		"\tpkts: %s\n",
		getTag().c_str(),
		protoStr[getProtocol()].c_str(),
		(duration != (uint32_t)-1) ? std::to_string(duration).c_str() : "-",
		mag_to_str(getBytes()).c_str(),
		tcpStr().c_str(),
		mag_to_str(getPkts()).c_str());

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
std::string NetV9_Value::toJsonString() {
	uint32_t duration = getDuration();

	//fill in char array
	char retCharArr[VAL_MAX_CHAR_LENGTH];
	int charsToBeWritten = sprintf(retCharArr,
		"\"tag\": \"%s\","
		"\"protocol\": \"%s\","
		"\"duration\": \"%s\","
		"\"bytes\": \"%s\","
		"\"conn_state\": \"%s\","
		"\"pkts\": \"%s\"",
		getTag().c_str(),
		protoStr[getProtocol()].c_str(),
		(duration != (uint32_t)-1) ? std::to_string(duration).c_str() : "-",
		mag_to_str(getBytes()).c_str(),
		tcpStr().c_str(),
	    mag_to_str(getPkts()).c_str());

	std::string ret = std::string(retCharArr);

	if(charsToBeWritten >= VAL_MAX_CHAR_LENGTH) {
		ret = ret.substr(0, VAL_MAX_CHAR_LENGTH-5) + std::string("...\n\n");
	}

	return ret;
}

/*
	Function to return binary representation of the data
			ewest - 06/23/18 updated: 07/27/18
*/
std::string NetV9_Value::toBinary() {
	std::string ret = std::string((char *)dbt.data, dbt.size);
	return ret;
}

//Variation of packData for netflow
//	ewest - 07/13/18
void NetV9_Value::packData(uint8_t source_id, transProto protocol, uint32_t duration,
	int bytes, uint8_t flags, int packets) {

	uint8_t magnitude;

	std::memcpy(vData + SOURCE_POS, &source_id, sizeof(uint8_t));
	
	std::memcpy(vData + PROTO_POS, &protocol, sizeof(uint8_t));
	debug(90, "Duration: %u\n", duration);
	std::memcpy(vData + DURATION_POS, &duration, sizeof(uint32_t));

	magnitude = log2(bytes);	// Convert to magnitude
	debug(90, "originBytes: %d -> %s\n", magnitude, mag_to_str(magnitude).c_str());
	std::memcpy(vData + BYTES_POS, &magnitude, sizeof(uint8_t));

	debug(90, "tcp_flags: %d\n", flags);
	std::memcpy(vData + TCP_POS, &flags, sizeof(uint8_t));

	// std::memcpy(ret + CONN_POS, &connectionState, sizeof(connEnum));
	magnitude = log2(packets);	// Convert to magnitude
	debug(90, "originPackets: %d -> %s\n", magnitude, mag_to_str(magnitude).c_str());
	std::memcpy(vData + PKTS_POS, &magnitude, sizeof(uint8_t));
}
