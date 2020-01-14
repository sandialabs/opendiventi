#include "bro_functions.h"
#include "IP_Key.h"
#include "Bro_Value.h"
#include "Bro_Parse.h"
#include "KeyValuePair.h"
#include "DiventiStream.h"
#include "SyslogHandler.h"

#include <vector>
#include <boost/algorithm/string.hpp>
#include <stdio.h>
#include <cstdlib>
#include <sstream>
#include <iostream>

#ifdef BRO_JSON
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#endif

//------------------------------------

Bro::~Bro() {}

//Function to identify and parse the header line (public)
bool Bro::parseFileFormat(std::string file, logFormat **format){
	debug(60, "identified bro\n");
	DiventiStream in(file);
#ifdef BRO_JSON
	// use first line of file to create format
	*format = createFormat("");
	bool done = true;
#else
	std::string *line;
	bool done = false;
	while (!done && in.good()){
		line = in.getLine();
		if (line){
			try {
				if (line->substr(0, 7) == "#fields"){
					// parseFields(line, format);
					*format = createFormat(*line);
					done = true;
				} 
				if (line->substr(0,1) != "#") {
					delete line;
					break; // optimization as fields should come at the beginning of every file
				}
				//else if (line->substr(0, 10) == "#separator"){

				// } else if (line->substr(0, 12) == "#unset_field"){

				// }
			} catch(std::out_of_range){}	// Ignore substr out of range errors
			delete line;
		}
	}
#endif
	return done;
}

//------------------------------------

//Function to parse bro buffers (public)
int Bro::parseBuf(char * buf, int size, logFormat **f, std::list<logEntry *> *results){

	BroFormat *fp = dynamic_cast<BroFormat *>(*f);
	BroEntry *e = new BroEntry();
	if (size< 20) {
		debug(20,"Got line too small: size: %d\n\t\'%s\'\n",
			  size,buf);
		delete e;
		return 0;
	}

	debug(80,"parsing line size: %d\n\t\'%s\'\n",
		  size,buf);
	// printf("%s\n", buf);

	#ifdef BRO_JSON

		// Loop through the buffer until the end
		// at each token look up the function to handle that 
		// and call it feeding the buffer and logEntry.
		int cur=0;      // current spot in buffer
		int tEnd=0;     // end of current token.
		int tNumb=0;    // the number of this token
		// int result;     // result from the token handler -- set to -1 if error.
		char endChar;   // the character at the end of the token.

		// seek to beginning of first value name which is after \"
		while(buf[cur++] != '\"' && cur < size) {}

		while (cur < size) {

			tEnd=cur;
			while (buf[tEnd] != '\"' && buf[tEnd]!=0 && tEnd < size){
				tEnd++;
			}

			endChar = buf[tEnd];
			buf[tEnd]=0;

			// we now have the name of the token

			debug(80,"token name found. cur:%d end:%d, %s\n",
				  cur,tEnd,buf+cur);

			// check if this matches any of our tokens
			for( int i = tNumb; i <= fp->lastToken; i++) {
				if(strcmp(buf+cur, fieldStr[fp->type[i]].c_str()) == 0) {
					// restore the string:
					buf[tEnd]=endChar;

					// set to i because json bro always comes in the same order
					// we set fp with this knowledge and any skipped fields
					// will not reoccur. Later we will increment to set up for that
					tNumb = i;

					// token begins 2 chars after end of key
					// or may have " which we'll need to stick
					cur = tEnd + 2;
					cur += (buf[cur] == '\"') ? 1:0;

					tEnd = cur;
					while (buf[tEnd] != '\"' && buf[tEnd] != ',' 
					&& buf[tEnd]!=0 && tEnd < size){
						tEnd++;
					}
					endChar = buf[tEnd];
					buf[tEnd]=0;

					debug(80, "token found. cur:%d end:%d, %s\n",
				  cur,tEnd,buf+cur);

					if (fp->fieldHandler[tNumb]!=nullptr){
						(*(fp->fieldHandler[tNumb]))(e,buf+cur);
					}
					tNumb++; // next field is after this one so +1
					break; //we found it so we're done looking
				}
			}

			// restore the string:
			buf[tEnd]=endChar;

			// seek to end of value
			while(buf[tEnd] != ',' && buf[tEnd] != 0 && tEnd < size)
				tEnd++;

			// If we've found the last token we care about
			// we're done.
			if (fp->lastToken<tNumb)
				break;

			// Move on to the next token.
			cur = tEnd+1;

			// seek to beginning of first value name which is after \"
			while(buf[cur++] != '\"' && cur < size) {}
		}



		// std::stringstream ss(buf);
		// boost::property_tree::ptree bro_data;

		// // this is hella slow 
		// boost::property_tree::read_json(ss, bro_data);
		
		// for(int tNumb = 0; tNumb <= fp->lastToken; tNumb++) {
		// 	logField name = fp->type[tNumb];
		// 	char *token = bro_data.get<char *>(boost::property_tree::ptree::path_type(fieldStr[name], '/'), nullptr);
		// 	if(token != nullptr) {
		// 		(*(fp->fieldHandler[tNumb]))(e, token);
		// 	}
		// }

		// extract the values we want from the json string



		// for(int tNumb = 0; tNumb <= fp->lastToken; tNumb++) {
		// 	logField name = fp->type[tNumb];
		// 	char *token = bro_data.get<char *>(boost::property_tree::ptree::path_type(fieldStr[name], '/'), nullptr);
		// 	if(token != nullptr) {
		// 		(*(fp->fieldHandler[tNumb]))(e, token);
		// 	}
		// }

	#else
		// Loop through the buffer until the end
		// at each token look up the function to handle that 
		// and call it feeding the buffer and logEntry.
		int cur=0;      // current spot in buffer
		int tEnd=0;     // end of current token.
		int tNumb=0;    // the number of this token
		// int result;     // result from the token handler -- set to -1 if error.
		char endChar;   // the character at the end of the token.

		// eat up whitespace at the front.
		while (isspace(buf[cur]) && cur <size)
			cur++;
		// #endif

		while (cur < size) {

			//  Find the end of this token and null terminate it.
			// #ifdef BRO_JSON
			// 	cur += (buf[++cur] == '\"') ? 1:0; // remove ':' and \" if present
			// 	tEnd=cur;
			// 	while(buf[tEnd] != '\"' && buf[tEnd] != ',' && buf[tEnd] != 0)
			// 		tEnd++;
			// #else
			tEnd=cur;
			while (!isspace(buf[tEnd]) && buf[tEnd]!=0 && tEnd <size){
				tEnd++;
			}
			// #endif

			// add a null terminator for this token.
			endChar = buf[tEnd];
			buf[tEnd]=0;
			debug(90,"found token end. cur:%d end:%d, %s\n",
				  cur,tEnd,buf+cur);

			/*  Parse the token here.
			 *   Look up the function for this token and call it.
			 */
			if (fp->fieldHandler[tNumb]!=nullptr){
				//result = (*(fp->fieldHandler[tNumb]))(this,buf+cur);
				(*(fp->fieldHandler[tNumb]))(e,buf+cur);
			}
			
			// For now No results checked as  it could just be an empty field.
			//  if (result==-1) {
			//		buf[tEnd]=endChar; 
					//debug(30, "Trouble parsing token %d on line:\n\t\'%s\'\n",
					//	  tNumb,buf);

			// restore the string:
			buf[tEnd]=endChar;

			// If we've found the last token we care about
			// we're done.
			if (fp->lastToken==tNumb)
				break;

			// Move on to the next token.
			cur = tEnd+1;
			tNumb++;

			// #ifdef BRO_JSON
			// 	// seek to beginning of first token (tokens seperated by)
			// 	while(buf[cur] != ':' && cur < size)
			// 		cur++;
			// #else
			// eat up whitespace at the front.
			while (isspace(buf[cur]) && cur <size)
				cur++;
			// #endif
		}

		if (fp->lastToken!=tNumb) {
			debug(30,"Warn: Parse didn't find all the tokens. found: %d tokens, expected: %d\nlogEntry: %s\n",
				  tNumb, fp->lastToken, e->toString().c_str());
		}
	#endif
	if (e->id_orig_h.s_addr == 0 && e->id_resp_h.s_addr == 0){
		debug(65, "Warning: trouble parsing on line '%s'\n", buf);
		delete e;
		return 0;
	}
	results->push_back(e);
	return 2;
}

KeyValuePair *Bro::createPair(uint8_t index, std::list<logEntry*> *results, uint8_t source) {
	BroEntry e;
	e = *results->front();
	//create the key using index as a marker of whether the key should be reversed
	//the first key will have index of 0 so false and next will be one so true
	IP_Key *key = new IP_Key(&(e.id_orig_h), e.ts , e.id_orig_p, 
			&(e.id_resp_h), e.id_resp_p, index);
	Bro_Value *value = new Bro_Value(source, e.proto, e.duration,
			e.orig_bytes, e.resp_bytes, e.conn_state,
			e.orig_pkts, e.resp_pkts, (const char *) &(e.uid));
	KeyValuePair *pair = new KeyValuePair(*key, *value);
	if( index % 2 != 0 ) {
		delete results->front();
		results->pop_front();
	}
	return pair;
}

//------------------------------

//function which uses diventiStream to read a line from the conn.log
int Bro::getRawData(char * buf, DiventiStream *stream){
	int size = stream->getLine(buf);
	if(buf[0] == '#') { // skip headers
		debug(85, "Header line read when reading log line\n");
		return 0;
	}
	return size;
}

//Function to read a line from the udp buffer
unsigned int Bro::getSyslogData(SyslogHandler *slh, char * buf, logFormat **fp) {
	unsigned int size = slh->getNextLine(buf, MAX_LINE, fp);
	return size;
}

Key *Bro::createKey(DBT *dbt) {
	IP_Key *key = new IP_Key(dbt);
	return key;
}

Value *Bro::createValue(DBT *dbt) {
	Bro_Value *value = new Bro_Value(dbt);
	return value;
}

std::string Bro::getHeader() {
	return "ts                  orig_ip          orig_port     resp_ip       resp_port     proto   duration   orig_byts     resp_byts      conn_state    orig_pkts    resp_pkts   uid";
}

/*
 * Retrieves the key for a file. The key is the first non-empty, non-comment line.
 * If no such lines exist, returns the file name.
 */
std::string Bro::getKey(std::string fileName){
	std::string* line;
	std::string ret = "";
	// Open the file
	DiventiStream ds(fileName);
	do{
		// If there are no more lines to get and no valid line has been found
		if (!ds.good()){
			ret = fileName;
			break;
		}
		debug(99, "Skipping line '%s'\n", ret.c_str());

		// Read a line
		line = ds.getLine();
		if (line != nullptr){
			ret = *line;
			delete line;
		}
	} while (ret.length() < 1 || ret.substr(0, 1) == "#");

	return ret;
}

logFormat *Bro::createFormat(std::string fields) {
	BroFormat *form = new BroFormat(fields);
	return form;
}

std::string Bro::getStats() {
	return "";
}