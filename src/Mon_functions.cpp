#include "Mon_functions.h"
#include "IP_Key.h"
#include "Mon_Value.h"
#include "Mon_Parse.h"
#include "KeyValuePair.h"
#include "DiventiStream.h"
#include "SyslogHandler.h"

#include <vector>
#include <boost/algorithm/string.hpp>
#include <stdio.h>
#include <cstdlib>
#include <sstream>
#include <string.h>

//------------------------------------

Mon::~Mon() {}

//  Little to be done here for Mon as the format is static.
//  So we just create the needed object and return it.
bool Mon::parseFileFormat(std::string file, logFormat **format){

	debug(60, "Parsing Mon file %s\n", file.c_str());        
        *format = createFormat(file);
        return true;
}

//------------------------------------


// Parse a log line from buf and produce a list on log entry objects.
//  returns... the number of entries?? 0 or 2. ?
//

int Mon::parseBuf(char * buf, int size, logFormat **f, std::list<logEntry *> *results){


        // Check if this is a logging message if if so ignore it.
        //   e.g.    2019-01-01T18:09:43-Tue logging started
        if (strstr(buf+22,"logging")!=nullptr) {
                debug(72, "Logging notice found in line %s\n",buf);
                return 0;
        }

        // Check min line size and send note...
	if (size< 47) {
		debug(20,"Got line too small: size: %d\n\t\'%s\'\n",
			  size,buf);
		return 0;
	}

	MonFormat *fp = dynamic_cast<MonFormat *>(*f);
	MonEntry *e = new MonEntry();
	debug(80,"parsing line size: %d\n\t\'%s\'\n",
		  size,buf);
	// printf("%s\n", buf);


        
	// Loop through the buffer until the end
	// at each token look up the function to handle that 
	// and call it feeding the buffer and logEntry.
	int cur=0;      // current spot in buffer
	int tEnd=0;     // end of current token.
	int tNumb=0;    // the number of this token
        //int result;     // result from the token handler -- set to -1 if error.
	char endChar;   // the character at the end of the token.

	// eat up whitespace at the front.
	while (isspace(buf[cur]) && cur <size)
		cur++;

        // The log parser knows this file is for a specific
        // protocol. So now copy this into the log entry.
        e->proto = fp->mon_proto;
        
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
		// if (fp->fieldHandler[tNumb]!=nullptr){
		// 	//result = (*(fp->fieldHandler[tNumb]))(this,buf+cur);
		// 	results = (*(fp->fieldHandler[tNumb]))(e,buf+cur);
		// }

                // if (result==-1) {
                //         buf[tEnd]=endChar; 
                //         debug(30, "Trouble parsing token %d on line:\n\t\'%s\'\n",
                //               tNumb,buf);
                //         delete e;
                //         return 0;
                // }
                
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
		debug(45, "Warning: trouble parsing on line '%s'\n", buf);
		delete e;
		return 0;
	}
	results->push_back(e);
	return 2;
}

KeyValuePair *Mon::createPair(uint8_t index, std::list<logEntry*> *results, uint8_t source) {
	MonEntry e;
	e = *results->front();
	//create the key using index as a marker of whether the key should be reversed
	//the first key will have index of 0 so false and next will be one so true
	IP_Key *key = new IP_Key(&(e.id_orig_h), e.ts , e.id_orig_p, 
			&(e.id_resp_h), e.id_resp_p, index);
	Mon_Value *value = new Mon_Value(source, e.proto, e.duration,
                                         e.orig_bytes, e.resp_bytes, e.connFlags);
        KeyValuePair *pair = new KeyValuePair(*key, *value);
	if( index % 2 != 0 ) {
		delete results->front();
		results->pop_front();
	}
	return pair;
}

//------------------------------

//function which uses diventiStream to read a line from the conn.log
int Mon::getRawData(char * buf, DiventiStream *stream){
	//define a function pointer which tells diventiStream
		//to read a line
	//Additionally define the maximum line size
	// stream->readIt = &std::istream::getline;
	// int size = stream->getData(buf, MAX_LINE);
	int size = stream->getLine(buf);
	return size;
}

//Function to read a line from the udp buffer
unsigned int Mon::getSyslogData(SyslogHandler *slh, char * buf, logFormat **fp) {
	unsigned int size = slh->getNextLine(buf, MAX_LINE, fp);
	return size;
}

Key *Mon::createKey(DBT *dbt) {
	IP_Key *key = new IP_Key(dbt);
	return key;
}

Value *Mon::createValue(DBT *dbt) {
        
	Mon_Value *value = new Mon_Value(dbt);
	return value;
}


std::string Mon::getHeader() {
	return "ts             orig_ip           o_port      resp_ip       r_port              src proto   duration    orig_bytes     resp_bytes      flags";
}

/*
 * Retrieves the key for a file. The key is the first non-empty, non-comment, non-header line
 * example mon header 2019-01-02T21:37:02-Wed logging started - type t
 * If no such lines exist, returns the file name.
 */
std::string Mon::getKey(std::string fileName){
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
	// keep checking for the line until correct line is found
	// the word logging is found at a specific position in all headers (see above)
	} while (ret.length() < 1 || ret.substr(0, 1) == "#" || ret.substr(24,30) == "logging");

	return ret;
}

logFormat *Mon::createFormat(std::string file) {
        transProto p=UNKNOWN_TRANSPORT;

        //
        //  Look at the first part of the file name (pulling off the path)
        //  to provide a heuristic to determine the protocol.
        //
        std::size_t name_p = file.find_last_of("/") +1;
        
        if (file.compare(name_p,3,"tcp")==0) {
                p=TCP;
        }
        if (file.compare(name_p,3,"udp")==0) {
                p=UDP;
        }
        if (file.compare(name_p,4,"icmp")==0) {
                p=ICMP;
        }
	MonFormat *form = new MonFormat(p);
	return form;
}

std::string Mon::getStats() {
	return "";
}
