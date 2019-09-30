#include "Basic_functions.h"
#include "Basic_Key.h"
#include "Basic_Value.h"
#include "Basic_Parse.h"
#include "KeyValuePair.h"
#include "DiventiStream.h"
#include "SyslogHandler.h"

#include <vector>
#include <boost/algorithm/string.hpp>
#include <stdio.h>
#include <cstdlib>
#include <sstream>

//------------------------------------

Basic::~Basic() {}

//Function to identify and parse the header line (public)
bool Basic::parseFileFormat(std::string file, logFormat **format){
	bool done = false;
	DiventiStream in(file);
	std::string *line;
	debug(60, "identified bro\n");
	while (!done && in.good()){
		line = in.getLine();
		if (line){
			try {
				if (line->substr(0, 7) == "#fields"){
					// parseFields(line, format);
					*format = createFormat(*line);
					done = true;
				} //else if (line->substr(0, 10) == "#separator"){

				// } else if (line->substr(0, 12) == "#unset_field"){

				// }
			} catch(std::out_of_range){}	// Ignore substr out of range errors
			delete line;
		}
	}
	return done;
}

//------------------------------------
//Function to parse bro buffers (public)
int Basic::parseBuf(char * buf, int size, logFormat **f, std::list<logEntry *> *results){
	// TODO put in a good min line size.
	BasicFormat *fp = dynamic_cast<BasicFormat *>(*f);
	BasicEntry *e = new BasicEntry();
	if (size< 10) {
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
	results->push_back(e);
	return 1;
}

KeyValuePair *Basic::createPair(uint8_t /*index*/, std::list<logEntry*> *results, uint8_t source) {
	BasicEntry e;
	e = *results->front();
	delete results->front();
	results->pop_front();

	//create the key using index as a marker of whether the key should be reversed
	//the first key will have index of 0 so false and next will be one so true
	Basic_Key *key = new Basic_Key(e.altitude);
	Basic_Value *value = new Basic_Value(source, (const char *) &(e.observation));
	KeyValuePair *pair = new KeyValuePair(*key, *value);
	return pair;
}

//------------------------------
//function which uses diventiStream to read a line from the conn.log
int Basic::getRawData(char * buf, DiventiStream *stream){
	//define a function pointer which tells diventiStream
		//to read a line
	//Additionally define the maximum line size
	int size = stream->getLine(buf);
	return size;
}

//Function to read a line from the udp buffer
unsigned int Basic::getSyslogData(SyslogHandler *slh, char * buf, logFormat **fp) {
	OPTIONS.syslogOffset = 0;
	unsigned int size = slh->getNextLine(buf, MAX_LINE, fp);
	return size;
}

Key *Basic::createKey(DBT *dbt) {
	Basic_Key *key = new Basic_Key(dbt);
	return key;
}

Value *Basic::createValue(DBT *dbt) {
	Basic_Value *value = new Basic_Value(dbt);
	return value;
}

std::string Basic::getHeader() {
	return "Altitude        Observations";
}

/*
 * Retrieves the key for a file. The key is the first non-empty, non-comment line.
 * If no such lines exist, returns the file name.
 */
std::string Basic::getKey(std::string fileName){
	std::string* line;
	std::string ret = "";
	// Open the file
	DiventiStream ds(fileName);
	do{
		// If there are no more lines to get and no valid line has been found
		if (!ds.good()){
			ret = fileName; // TODO fix to work with ds.getLine(), which returns a string*
			break;
		}
		debug(99, "Skipping line '%s'\n", ret.c_str());

		// Read a line
		line = ds.getLine();
		if (line != nullptr){
			ret = *line;
			delete line;
		}
	} while (ret.length() < 1);

	return ret;
}

logFormat *Basic::createFormat(std::string fields) {
	BasicFormat *form = new BasicFormat(fields);
	return form;
}