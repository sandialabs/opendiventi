#include "Basic_Parse.h"
#include "diventi.h"
#include "Basic_Value.h"
#include "DiventiStream.h"

#include <vector>
#include <boost/algorithm/string.hpp>
#include <stdio.h>
#include <cstdlib>
#include <sstream>



std::string const BasicFormat::fieldStr[] = {"altitude", "observation", "UNUSED", "UNKNOWN"};

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

static int altitudeHandler(logEntry *e, char *s) {
        BasicEntry* be = static_cast<BasicEntry*> (e);
        be->altitude = strtol(s, nullptr, 10);
	return 0;
}

static int observationHandler(logEntry *e, char *s) {
        BasicEntry* be = static_cast<BasicEntry*> (e);
	int l = strlen(s);
	if(l>Basic_Value::OBS_SIZE) {
		debug(25,"Warning: Observation not correct size \'%s\' is %d\n",s,l);
	}
	memcpy(be->observation, s, l);
	if(l < Basic_Value::OBS_SIZE) {
		be->observation[l] = 0;
	}
	return 0;
}

BasicFormat::BasicFormat(std::string fields) {
	for (int i = 0; i < MAX_FIELDS; i++){
		type[i] = UNUSED;
		fieldHandler[i]=nullptr;
	}
	parse(fields);
}

BasicFormat::BasicFormat(){
	for (int i = 0; i < MAX_FIELDS; i++){
		type[i] = UNUSED;
		fieldHandler[i]=nullptr;
	}
}

bool BasicFormat::operator==(const logFormat& other){
	return !memcmp(type, dynamic_cast<const BasicFormat &>(other).type, MAX_FIELDS * sizeof(logField));
}

BasicFormat *BasicFormat::operator=(const logFormat& other){
	for (int i = 0; i < MAX_FIELDS; i++){
		type[i] = dynamic_cast<const BasicFormat &>(other).type[i];
	}
	return this;
}

std::string BasicFormat::toString() const{
	std::stringstream str;
	str << "Log format:\n";
	for (int i = 0; i < MAX_FIELDS && type[i] != UNUSED; i++){
		str << i << ": " << fieldStr[type[i]] << "\n";
	}
	return str.str();
}

//Parsing functions for the header
//function that actually does the parsing of the header line
void BasicFormat::parse(std::string fields){
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
		if (toks[i] == fieldStr[ALTITUDE]){
			type[i] = ALTITUDE;
			lastToken=i;
			fieldHandler[i] = altitudeHandler;
		} else if (toks[i] == fieldStr[OBSERVATION]){
			type[i] = OBSERVATION;
			lastToken=i;
			fieldHandler[i] = observationHandler;
		} else{
			type[i] = UNKNOWN;
		}
		// debug(30, "Entry %d is of type '%s' (enum %d)\n", i, toks[i].c_str(), type[i]);
	}

	debug(60, "Fields Parsed lastToken:%d\n%s\n", lastToken, toString().c_str());
}

BasicEntry::BasicEntry(){
	altitude = 0;
	observation[0] = 0;
}

BasicEntry::~BasicEntry(){
}

bool BasicEntry::operator==( logEntry& oth){
	// Some fields not currently used
	BasicEntry &other = dynamic_cast<BasicEntry &>(oth);
	return (altitude == other.altitude) && (strncmp(observation, other.observation, Basic_Value::OBS_SIZE) == 0);
}

BasicEntry *BasicEntry::operator=(const logEntry& oth){
	const BasicEntry &other = dynamic_cast<const BasicEntry &>(oth);
	altitude = other.altitude;
	memcpy(observation,other.observation,Basic_Value::OBS_SIZE);
	return this;
}

std::string BasicEntry::toString(){
	// Only the fields we care about
	std::stringstream str;
	str << "Log entry:\n";
	str << "altitude: " << altitude << "\n";
	str << "observation: " << observation << "\n";
	return str.str();
}
