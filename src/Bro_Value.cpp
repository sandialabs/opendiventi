#include "Bro_Value.h"
#include "diventi.h"

#include <tokudb.h>

/*
	The value is the parts of the log that don't include the ips, ports, or timestamp
	includes: protocol, duration, bytes transfered and recieved, and so on
*/

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

Bro_Value::Bro_Value(uint8_t source, transProto protocol, uint32_t duration, int originBytes,
	int destinationBytes, connEnum connectionState, int originPackets,
	int destinationPackets, const char* uid) {
	dbt.data = & vData;
	packData(source, protocol, duration, originBytes,
			 destinationBytes, connectionState, originPackets, 
			 destinationPackets, uid);
	//dbt.flags |= DB_DBT_MALLOC;
	dbt.flags=0;
	dbt.size = VALUE_SIZE;
	dbt.ulen = VALUE_SIZE;
}

Bro_Value::Bro_Value(DBT* d) {
	dbt.data = & vData;

	memcpy(dbt.data, d->data, d->size);
	dbt.flags = d->flags;
	dbt.size = d->size;
	dbt.ulen = d->ulen;

}

Bro_Value::Bro_Value(byte* data) {
	dbt.data = & vData;

	memcpy(dbt.data, data, VALUE_SIZE);
	//dbt.flags |= DB_DBT_MALLOC;
	dbt.flags =0;
	dbt.size = VALUE_SIZE;
	dbt.ulen = VALUE_SIZE;
}

Bro_Value::Bro_Value(const Bro_Value& v){
	dbt.data = & vData;

	memcpy(dbt.data, v.getDBT()->data, VALUE_SIZE);
	//dbt.flags |= DB_DBT_MALLOC;
	dbt.flags =0;
	dbt.size = VALUE_SIZE;
	dbt.ulen = VALUE_SIZE;
}

Bro_Value::Bro_Value(const Value& v){
	dbt.data = & vData;

	memcpy(dbt.data, dynamic_cast<const Bro_Value &>(v).getDBT()->data, VALUE_SIZE);
	//dbt.flags |= DB_DBT_MALLOC;
	dbt.flags =0;
	dbt.size = VALUE_SIZE;
	dbt.ulen = VALUE_SIZE;
}

Bro_Value::~Bro_Value() {
}

DBT* Bro_Value::getDBT() const{
	return (DBT*) &dbt;
}

Bro_Value *Bro_Value::operator=(const Value *other){
	memcpy(dbt.data, other->getDBT()->data, VALUE_SIZE);
	dbt.flags |= DB_DBT_MALLOC;
	dbt.size = VALUE_SIZE;
	dbt.ulen = VALUE_SIZE;
	return this;
}

bool Bro_Value::operator==(const Value& other) {
	return (memcmp(dbt.data, other.getDBT()->data, dbt.size) == 0);
}

bool Bro_Value::operator!=(const Value& other) {
	return !(*this == other);
}

std::string Bro_Value::getTag() {
	uint8_t src = (uint8_t) ((char *)dbt.data)[0];
	return OPTIONS.sources[src]->tag;
}

transProto Bro_Value::getProtocol() {
	return (transProto)(*((uint8_t*) ((byte*)dbt.data + PROTO_CONN_POS)) & 0xf);	// Lowest 4 bits
}

uint32_t Bro_Value::getDuration() {
	return *((uint32_t*) ((byte*)dbt.data + DURATION_POS));
}

uint8_t Bro_Value::getOrigBytes() {
	return *((uint8_t*) ((byte*)dbt.data + ORIGIN_BYTES_POS));
}

uint8_t Bro_Value::getRespBytes() {
	return *((uint8_t*) ((byte*)dbt.data + DEST_BYTES_POS));
}

connEnum Bro_Value::getConnState() {
	return  (connEnum)(*((uint8_t*) ((byte*)dbt.data + PROTO_CONN_POS)) >> 4);	// Highest 4 bytes
}

uint8_t Bro_Value::getOrigPkts() {
	return *((uint8_t*) ((byte*)dbt.data + ORIGIN_PKTS_POS));
}

uint8_t Bro_Value::getRespPkts() {
	return *((uint8_t*) ((byte*)dbt.data + DEST_PKTS_POS));
}

char * Bro_Value::getUid() {
	return  ((char*) dbt.data + UID_POS);
}

/*
proto				duration	orig_bytes	resp_bytes	conn_state	orig_pkts	resp_pkts
tcp					-			0			0			RSTRH		0			[1, 3)	
icmp				-			0			0			RSTRH		0			[1, 3)	
proto				duration	orig_bytes	resp_bytes	conn_state	orig_pkts	resp_pkts
*/

std::string Bro_Value::toString() {
	uint32_t duration = getDuration();
	char uid[BRO_UID_SIZE+1]; // +1 for null term.
	std::string state;
	memcpy(uid,getUid(),BRO_UID_SIZE);
	uid[BRO_UID_SIZE]=0;
	char retCharArr[VAL_MAX_CHAR_LENGTH];
	
	//fill in char array
	int charsToBeWritten;
	charsToBeWritten = sprintf(retCharArr,
		"%-12s   %-5s   %-8s   %-17s  %-17s  %-9s   %-10s  %-10s  %18s",	// source tag, protocol, duration, orig bytes, resp bytes, conn state, orig packts, resp packets, uid
		getTag().c_str(),
		protoStr[getProtocol()].c_str(),
		(duration != (uint32_t)-1) ? std::to_string(duration).c_str() : "-",
		mag_to_str(getOrigBytes()).c_str(),
		mag_to_str(getRespBytes()).c_str(),
		connStr[getConnState()].c_str(),
		mag_to_str(getOrigPkts()).c_str(),
		mag_to_str(getRespPkts()).c_str(),
		uid
	);

	
	

	std::string ret = std::string(retCharArr);

	if(charsToBeWritten >= VAL_MAX_CHAR_LENGTH) {
		ret = ret.substr(0, VAL_MAX_CHAR_LENGTH-5) + std::string("...\n\n");
	}

	return ret;
}

std::string Bro_Value::toVerboseString() {
	return toString();
}

std::string Bro_Value::toExtendedString() {
	uint32_t duration = getDuration();
	char uid[BRO_UID_SIZE+1]; // +1 for null term.
	memcpy(uid,getUid(),BRO_UID_SIZE);
	uid[BRO_UID_SIZE]=0;

	//fill in char array
	char retCharArr[VAL_MAX_CHAR_LENGTH];
	int charsToBeWritten = sprintf(retCharArr,
		"\ttag: %s\n"
		"\tprotocol: %s\n"
		"\tduration: %s\n"
		"\torigin bytes: %s\n"
		"\tresp_bytes: %s\n"
		"\tconnection state: %s\n"
		"\torig_pkts: %s\n"
		"\tresp_pkts: %s\n"
		"\tuid: %s\n",
		getTag().c_str(),
		protoStr[getProtocol()].c_str(),
		(duration != (uint32_t)-1) ? std::to_string(duration).c_str() : "-",
		mag_to_str(getOrigBytes()).c_str(),
		mag_to_str(getRespBytes()).c_str(),
		connStr[getConnState()].c_str(),
		mag_to_str(getOrigPkts()).c_str(),
	    mag_to_str(getRespPkts()).c_str(),
		uid);

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
std::string Bro_Value::toJsonString() {
	uint32_t duration = getDuration();
	char uid[BRO_UID_SIZE+1]; // +1 for null term.
	memcpy(uid,getUid(),BRO_UID_SIZE);
	uid[BRO_UID_SIZE]=0;

	//fill in char array
	char retCharArr[VAL_MAX_CHAR_LENGTH];
	int charsToBeWritten = sprintf(retCharArr,
		"\"tag\": \"%s\","
		"\"protocol\": \"%s\","
		"\"duration\": \"%s\","
		"\"origin_bytes\": \"%s\","
		"\"resp_bytes\": \"%s\","
		"\"conn_state\": \"%s\","
		"\"orig_pkts\": \"%s\","
		"\"resp_pkts\": \"%s\","
		"\"uid\": \"%s\"",
		getTag().c_str(),
		protoStr[getProtocol()].c_str(),
		(duration != (uint32_t)-1) ? std::to_string(duration).c_str() : "-",
		mag_to_str(getOrigBytes()).c_str(),
		mag_to_str(getRespBytes()).c_str(),
		connStr[getConnState()].c_str(),
		mag_to_str(getOrigPkts()).c_str(),
	    mag_to_str(getRespPkts()).c_str(),
		uid);

	std::string ret = std::string(retCharArr);

	if(charsToBeWritten >= VAL_MAX_CHAR_LENGTH) {
		ret = ret.substr(0, VAL_MAX_CHAR_LENGTH-5) + std::string("...\n\n");
	}

	return ret;
}


/*
 *  Packs the data without calling alloc etc.
 */
void Bro_Value::packData(uint8_t source_id, transProto protocol, uint32_t duration,
	int originBytes, int destinationBytes, connEnum connectionState,
	int originPackets, int destinationPackets, const char * uid) {

	uint8_t magnitude, proto_conn;

	std::memcpy(vData + SOURCE_POS, &source_id, sizeof(uint8_t));
	
	proto_conn = protocol | (connectionState << 4);
	std::memcpy(vData + PROTO_CONN_POS, &proto_conn, sizeof(uint8_t));

	debug(90, "Duration: %d (unsigned %u)\n", duration, duration);
	std::memcpy(vData + DURATION_POS, &duration, sizeof(uint32_t));

	magnitude = log2(originBytes);	// Convert to magnitude
	debug(90, "originBytes: %d -> %s\n", magnitude, mag_to_str(magnitude).c_str());
	std::memcpy(vData + ORIGIN_BYTES_POS, &magnitude, sizeof(uint8_t));

	magnitude = log2(destinationBytes);	// Convert to magnitude
	debug(90, "destBytes: %d -> %s\n", magnitude, mag_to_str(magnitude).c_str());
	std::memcpy(vData + DEST_BYTES_POS, &magnitude, sizeof(uint8_t));

	// std::memcpy(ret + CONN_POS, &connectionState, sizeof(connEnum));
	magnitude = log2(originPackets);	// Convert to magnitude
	debug(90, "originPackets: %d -> %s\n", magnitude, mag_to_str(magnitude).c_str());
	std::memcpy(vData + ORIGIN_PKTS_POS, &magnitude, sizeof(uint8_t));

	magnitude = log2(destinationPackets);	// Convert to magnitude
	debug(90, "destPkts: %d -> %s\n", magnitude, mag_to_str(magnitude).c_str());
	std::memcpy(vData + DEST_PKTS_POS, &magnitude, sizeof(uint8_t));
	
	std::memcpy(vData + UID_POS, uid, BRO_UID_SIZE);
}
