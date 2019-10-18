#include "netAscii_functions.h"
#include "diventi.h"
#include "IP_Key.h"
#include "Net_Value.h"
#include "KeyValuePair.h"
#include "DiventiStream.h"
#include "SyslogHandler.h"

#include <vector>
#include <boost/algorithm/string.hpp>
#include <stdio.h>
#include <cstdlib>
#include <sstream>

bool NetAscii::parseFileFormat(std::string file, logFormat **format){
	bool done = false;
	DiventiStream in(file);
	std::string *line;
	debug(60, "identified netAscii\n");
	while (!done && in.good()){
		line = in.getLine();
		if (line){
			try {
				debug(120, "%s\n", line->substr(0,3).c_str());
				if ( line->substr(0, 7) == "#fields"){
					debug(40, "Found fields\n");
					*format = createFormat(*line);
					done = true;
				} //else if (line->substr(0, 10) == "#separator"){

				// } else if (line->substr(0, 12) == "#unset_field"){

				// }
			} catch(std::out_of_range){}	// Ignore substr out of range errors
			delete line;
		}
	}
	if(!done) {
		debug(0, "Potentially incorrect log format\n#fields header must be added to netflow file, run with debug = 10 to see an example\n");
		debug(10, "#fields ts id.orig_h id.orig_p id.resp_h id.resp_p proto duration orig_bytes resp_bytes tcp_flags orig_pkts resp_pkts\n");
	}
	return done;
}

//------------------------------------
//Function to parse netAscii buffers (public)
int NetAscii::parseBuf(char * buf, int size, logFormat **f, std::list<logEntry *> *results){
	NetFormat *fp = dynamic_cast<NetFormat *>(*f);
	NetEntry *e = new NetEntry();

	if (size< 20) {
		debug(20,"Got line too small: size: %d\n\t\'%s\'\n",
			  size,buf);
		return 0;
	}

	debug(80,"parsing line size: %d\n\t\'%s\'\n",
		  size,buf);

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

	while (cur < size) {

		//  Find the end of this token and null terminate it.
		tEnd=cur;
		while (!isspace(buf[tEnd]) && buf[tEnd]!=0 && tEnd <size){
			tEnd++;
		}
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

		while (isspace(buf[cur]) && cur <size)
			cur++;
	}

	if (fp->lastToken!=tNumb) {
		debug(30,"Warn: Parse didn't find all the tokens. found: %d tokens, expected: %d\n",
			  tNumb, fp->lastToken);
	}
	if (e->id_orig_h.s_addr == 0 && e->id_resp_h.s_addr == 0){
		debug(55, "Warning: trouble parsing on line '%s'\n", buf);
		return 0;
	}
	results->push_back(e);
	return 2;
}

KeyValuePair *NetAscii::createPair(uint8_t index, std::list<logEntry*> *results, uint8_t source) {
	NetEntry e;
	e = *results->front();
	if( index % 2 != 0 ) {
		delete results->front();
		results->pop_front();
	}

	//create the key using index as a marker of whether the key should be reversed
	//the first key will have index of 0 so false and next will be one so true
	IP_Key *key = new IP_Key(&(e.id_orig_h), e.ts , e.id_orig_p, 
			&(e.id_resp_h), e.id_resp_p, index);
	Net_Value *value = new Net_Value(source, e.proto, e.duration,
			e.bytes, e.tcp_flags, e.pkts);
	KeyValuePair *pair = new KeyValuePair(*key, *value);
	return pair;
}

//------------------------------
//function which uses diventiStream to read a line from the netAscii log
int NetAscii::getRawData(char * buf, DiventiStream *stream){
	//define a function pointer which tells diventiStream
		//to read a line or read a certain amount of bytes
	//Additionally define the number of bytes to read or the maximum line size

	int size = stream->getLine(buf);
	return size;
}

//Function to read a line from the udp buffer
unsigned int NetAscii::getSyslogData(SyslogHandler *slh, char * buf, logFormat **fp) {
	OPTIONS.syslogOffset = 0;
	unsigned int size = slh->getNextLine(buf, MAX_LINE, fp);
	return size;
}

Key *NetAscii::createKey(DBT *dbt) {
	IP_Key *key = new IP_Key(dbt);
	return key;
}

Value *NetAscii::createValue(DBT *dbt) {
	Net_Value *value = new Net_Value(dbt);
	return value;
}

std::string NetAscii::getHeader() {
	return "ts           orig_ip   orig_port   resp_ip     resp_port    proto   duration   bytes  tcp_flags  packets";
}

/*
 * Retrieves the key for a file. The key is the first non-empty, non-comment line.
 * If no such lines exist, returns the file name.
 */
std::string NetAscii::getKey(std::string fileName){
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

logFormat *NetAscii::createFormat(std::string fields) {
	NetFormat *form = new NetFormat(fields);
	return form;
}

std::string NetAscii::getStats() {
	//will eventually want to put counts of dropped packets and such things here
	return "";
}