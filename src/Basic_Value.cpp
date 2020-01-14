#include "Basic_Value.h"
#include "diventi.h"

#include <tokudb.h>

Basic_Value::Basic_Value(uint8_t source, const char* observation) {
	dbt.data = & vData;
	packData(source, observation);
	//dbt.flags |= DB_DBT_MALLOC;
	dbt.flags=0;
	dbt.size = VALUE_SIZE;
	dbt.ulen = VALUE_SIZE;
}

Basic_Value::Basic_Value(DBT* d) {
	dbt.data = & vData;

	memcpy(dbt.data, d->data, d->size);
	dbt.flags = d->flags;
	dbt.size = d->size;
	dbt.ulen = d->ulen;
}

Basic_Value::Basic_Value(byte* data) {
	dbt.data = & vData;

	memcpy(dbt.data, data, VALUE_SIZE);
	//dbt.flags |= DB_DBT_MALLOC;
	dbt.flags =0;
	dbt.size = VALUE_SIZE;
	dbt.ulen = VALUE_SIZE;
}

Basic_Value::Basic_Value(const Basic_Value& v){
	dbt.data = & vData;

	memcpy(dbt.data, v.getDBT()->data, VALUE_SIZE);
	//dbt.flags |= DB_DBT_MALLOC;
	dbt.flags =0;
	dbt.size = VALUE_SIZE;
	dbt.ulen = VALUE_SIZE;
}

Basic_Value::Basic_Value(const Value& v){
	dbt.data = & vData;

	memcpy(dbt.data, dynamic_cast<const Basic_Value &>(v).getDBT()->data, VALUE_SIZE);
	//dbt.flags |= DB_DBT_MALLOC;
	dbt.flags =0;
	dbt.size = VALUE_SIZE;
	dbt.ulen = VALUE_SIZE;
}

Basic_Value::~Basic_Value() {
}

DBT* Basic_Value::getDBT() const{
	return (DBT*) &dbt;
}

Basic_Value *Basic_Value::operator=(const Value *other){
	memcpy(dbt.data, other->getDBT()->data, VALUE_SIZE);
	dbt.flags |= DB_DBT_MALLOC;
	dbt.size = VALUE_SIZE;
	dbt.ulen = VALUE_SIZE;
	return this;
}

bool Basic_Value::operator==(const Value& other) {
	return (memcmp(dbt.data, other.getDBT()->data, dbt.size) == 0);
}

bool Basic_Value::operator!=(const Value& other) {
	return !(*this == other);
}

std::string Basic_Value::getTag() {
	uint8_t src = (uint8_t) ((char *)dbt.data)[0];
	return OPTIONS.sources[src]->tag;
}

char * Basic_Value::getObservation() {
	return  ((char*) dbt.data + OBS_POS);
}

/*
proto				duration	orig_bytes	resp_bytes	conn_state	orig_pkts	resp_pkts
tcp					-			0			0			RSTRH		0			[1, 3)	
icmp				-			0			0			RSTRH		0			[1, 3)	
proto				duration	orig_bytes	resp_bytes	conn_state	orig_pkts	resp_pkts
*/

std::string Basic_Value::toString() {
	char obs[OBS_SIZE+1]; // +1 for null term.
	memcpy(obs,getObservation(),OBS_SIZE);
	obs[OBS_SIZE]=0;
	
	//fill in char array
	char retCharArr[VAL_MAX_CHAR_LENGTH];
	int charsToBeWritten = sprintf(retCharArr,
		"%-12s   %40s",
		getTag().c_str(),
		obs
	);

	std::string ret = std::string(retCharArr);

	if(charsToBeWritten >= VAL_MAX_CHAR_LENGTH) {
		ret = ret.substr(0, VAL_MAX_CHAR_LENGTH-5) + std::string("...\n\n");
	}

	return ret;
}

std::string Basic_Value::toVerboseString() {
	return toString();
}

std::string Basic_Value::toExtendedString() {
char obs[OBS_SIZE+1]; // +1 for null term.
	memcpy(obs,getObservation(),OBS_SIZE);
	obs[OBS_SIZE]=0;

	//fill in char array
	char retCharArr[VAL_MAX_CHAR_LENGTH];
	int charsToBeWritten = sprintf(retCharArr,
		"\ttag: %s\n"
		"\tobservation: %s\n",
		getTag().c_str(),
		obs);

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
std::string Basic_Value::toJsonString() {
	char obs[OBS_SIZE+1]; // +1 for null term.
	memcpy(obs,getObservation(),OBS_SIZE);
	obs[OBS_SIZE]=0;

	//fill in char array
	char retCharArr[VAL_MAX_CHAR_LENGTH];
	int charsToBeWritten = sprintf(retCharArr,
		"\"tag\": \"%s\""
		"\"observation\": \"%s\"",
		getTag().c_str(),
		obs);

	std::string ret = std::string(retCharArr);

	if(charsToBeWritten >= VAL_MAX_CHAR_LENGTH) {
		ret = ret.substr(0, VAL_MAX_CHAR_LENGTH-5) + std::string("...\n\n");
	}

	return ret;
}


/*
 *  Packs the data without calling alloc etc.
 */
void Basic_Value::packData(uint8_t source, const char * observation) {
	std::memcpy(vData + SOURCE_POS, &source, sizeof(uint8_t));
	std::memcpy(vData + OBS_POS, observation, OBS_SIZE);
}
