#include "Basic_Key.h"
#include "diventi.h"

#include <tokudb.h>
#include <endian.h>

/*
	The key is the timestamp of the log, the ip addresses, and the ports used
*/


Basic_Key::Basic_Key( uint32_t altitude){

	dbt.data = &keyData;
	
	packData(altitude);

	//dbt.flags |= DB_DBT_MALLOC;
	dbt.flags =0;
	dbt.size = KEY_SIZE;
	dbt.ulen = KEY_SIZE;
	KEY_BYTES = 4;
}

Basic_Key::Basic_Key(DBT* d) {
	dbt.data = &keyData;	
	memcpy(this->dbt.data, d->data, d->size);
	this->dbt.flags = d->flags;
	this->dbt.size = d->size;
	this->dbt.ulen = d->ulen;
	KEY_BYTES = 4;
}

Basic_Key::Basic_Key(byte* data) {
	dbt.data = &keyData;
	memcpy(dbt.data, data, KEY_SIZE);
	//dbt.flags |= DB_DBT_MALLOC;
	dbt.flags =0;
	dbt.size = KEY_SIZE;
	dbt.ulen = KEY_SIZE;
	KEY_BYTES = 4;
}

Basic_Key::Basic_Key(const Basic_Key& key){
	dbt.data = &keyData;
	memcpy(dbt.data, key.getDBT()->data, KEY_SIZE);
	//dbt.flags |= DB_DBT_MALLOC;
	dbt.flags =0;
	dbt.size = KEY_SIZE;
	dbt.ulen = KEY_SIZE;
	KEY_BYTES = 4;
}

Basic_Key::Basic_Key(const Key& key){
	dbt.data = &keyData;
	memcpy(dbt.data, dynamic_cast<const Basic_Key &>(key).getDBT()->data, KEY_SIZE);
	//dbt.flags |= DB_DBT_MALLOC;
	dbt.flags =0;
	dbt.size = KEY_SIZE;
	dbt.ulen = KEY_SIZE;
	KEY_BYTES = 4;
}

Basic_Key::~Basic_Key() {
}

Basic_Key *Basic_Key::operator=(const Key *other){
	memcpy(dbt.data, other->getDBT()->data, KEY_SIZE);
	//dbt.flags |= DB_DBT_MALLOC;
	dbt.flags =0;
	dbt.size = KEY_SIZE;
	dbt.ulen = KEY_SIZE;
	KEY_BYTES = 4;
	return this;
}

DBT* Basic_Key::getDBT() const{
	return (DBT*) &dbt;
}

bool Basic_Key::operator==(const Key& other) {
	return !memcmp(dbt.data, other.getDBT()->data, KEY_SIZE);
}

bool Basic_Key::operator!=(const Key& other) {
	return !(*this == other);
}

uint32_t Basic_Key::getAltitude() {
	return be32toh(*((uint32_t*) ((byte*)dbt.data + ALTITUDE_POS)));
}

std::string Basic_Key::toString() {	

	//fill in char array
	char retCharArr[KEY_MAX_CHAR_LENGTH];
	uint32_t altitude = getAltitude();
	int charsToBeWritten = sprintf(retCharArr, 
		"%-10u",
		altitude
	);

	std::string ret = std::string(retCharArr);

	if(charsToBeWritten >= KEY_MAX_CHAR_LENGTH) {
		ret = ret.substr(0, KEY_MAX_CHAR_LENGTH-5) + std::string("...\n\n");
	}

	return ret;
}

std::string Basic_Key::toVerboseString() {
	return toString();
}

std::string Basic_Key::toExtendedString() {

	//fill in char array
	char retCharArr[KEY_MAX_CHAR_LENGTH];
	uint32_t altitude = getAltitude();
	int charsToBeWritten = sprintf(retCharArr, 
		"\taltitude: %u\n",
		altitude
	);

	std::string ret = std::string(retCharArr);

	if(charsToBeWritten >= KEY_MAX_CHAR_LENGTH) {
		ret = ret.substr(0, KEY_MAX_CHAR_LENGTH-5) + std::string("...\n\n");
	}

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
std::string Basic_Key::toJsonString() {

	//fill in char array
	char retCharArr[KEY_MAX_CHAR_LENGTH];
	uint32_t altitude = getAltitude();
	int charsToBeWritten = sprintf(retCharArr, 
		"\"altitude\": \"%u\",",
		altitude
	);

	std::string ret = std::string(retCharArr);

	//if the output is too big... shorten it
	if(charsToBeWritten >= KEY_MAX_CHAR_LENGTH) {
		ret = ret.substr(0, KEY_MAX_CHAR_LENGTH-5) + std::string("...\n\n");
	}

	return ret;
}

/*
 *  Does same as binPack w/o alloc
 *    Takes the data elements and packs them into the 
 *    Keys' data without all the allocating of the predecessor.
 */
void Basic_Key::packData(uint32_t altitude) {

	byte *ret;
	ret = keyData.data;

	// All members must be in big endian for keyCompare to work     
	altitude = htobe32(altitude);    
	memcpy(ret + ALTITUDE_POS, &altitude, sizeof(uint32_t));
}

//Returns the argument in a string->string map specified by name "ip"
static uint32_t firstALT(std::map<std::string, std::string> &args){
	return std::stoul(args["ip"]);
}

//Returns either the same thing that firstIP returned or returns the lastIP
static uint32_t lastALT(std::map<std::string, std::string> &args){
	if (args.count("range") == 0){
		return std::stoul(args["ip"]);
	} else{
		return std::stoul(args["range"]);
	}
}

//Function that parses the url arguments and returns the Key which denotes the
//	first valid index
Key *Basic_Key::createFirstKey(std::map<std::string, std::string> &args) {
	uint32_t start = firstALT(args);
	debug(40, "start value: %u\n", start);
	Basic_Key *startKey = new Basic_Key(start);
	return startKey;
}

//Function that creates the last valid index and returns it
Key *Basic_Key::createLastKey(std::map<std::string, std::string> &args) {
	uint32_t last = lastALT(args);
	debug(40, "end value: %u\n", last);
	Basic_Key *endKey = new Basic_Key(last);
	return endKey;
}