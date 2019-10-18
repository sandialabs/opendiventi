#include "InsertThread.h"
#include "diventi.h"
#include "FileHandler.h"
#include "TokuHandler.h"
#include "SyslogHandler.h"
#include "KeyValuePair.h"

#include <fstream>
#include <string>
#include <mutex>
#include <boost/thread.hpp>
#include <boost/chrono.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

InsertThread::InsertThread(TokuHandler *handler, FileHandler *fH, 
						   SyslogHandlerHandler *slhh, int i) {
	tokuHandler = handler;
	fileHandler = fH;
	this->slhh = slhh;
	t = nullptr;
	thNum = i;
	//set the variables that control how the semi-unique numbers are created
	//semi-unique numbers are for key creation and help to distinquish identical keys
	// shift = 8 - ceil(log2(OPTIONS.insertThreads));
	// shift = (shift > 0 && OPTIONS.insertThreads != 1) ? shift : 0;
	// mask = pow(2, shift) - 1;
	// debug(20, "shift: %d, mask: %d\n", shift, mask);
}

InsertThread::~InsertThread() {
	debug(5,"(%d) Joining insertion thread\n",thNum);
	debug(5,"t:%p\n",t);
	if (t != nullptr && t->joinable()){
		debug(65,"is joinable\n");
		t->interrupt();
		t->join();
	}
	debug(5,"(%d) Deleting insertion thread\n",thNum);

	delete t;
	debug(5,"(%d) Insertion thread deleted\n",thNum);
}

void InsertThread::run() {
	debug(65,"Insertion Thread started\n");
	numInserted = 0;
	if (OPTIONS.continuous || OPTIONS.syslog){
		while(1) {
			if (!readLog()){
				//if we got false (no data over syslog or from the file) then we should delay before querying again
				debug(80, "Data could not be collected. Thread sleeping for 25 milliseconds\n");
				boost::this_thread::sleep_for(boost::chrono::milliseconds(25));
			}
			boost::this_thread::interruption_point();
		}
	} else {
		while(readLog()) {
			boost::this_thread::interruption_point();
		}
	}
	

	debug(95,"(%d) thread shutting down\n",thNum);
}

void InsertThread::thread(){
	t = new boost::thread(boost::bind(&InsertThread::run,this));
	debug(50,"(%d) new inserter thread at (%p)\n",thNum,t);
}

/*
 *	readLog()
 *    	reads data from the log, parses it and insert a pair of key values.
 *		Based on the setup in run() will either read a line or will read 48 bytes
 *   	This is the main routine that reads and processes lines.
 *    	It is the core operation of the insertion threads and should
 *    	avoid allocating and deleting memory.
 *	Returns false if we weren't able to find any lines.  
 *     	Otherwise returns true.
 *			ewest - (updated) 07/24/18
 */
bool InsertThread::readLog(){
	logFormat *fp; // This local is filled by whoever gives us the log line
                     // They fill it with an object that can parse the line.

	char buf[MAX_LINE]; // buffer to be used for hold the read data
	int  size=0;  // size of the line read
	
	// Check for a line from syslog
	if (slhh != nullptr) {
		// std::chrono::time_point<std::chrono::system_clock> start = std::chrono::system_clock::now();
		uint8_t source;
		size = slhh->getData(buf, &fp, &src, &source);
		// std::chrono::duration<double> diff = std::chrono::system_clock::now() - start;
		// printf("Syslog: %s\n", std::to_string(diff.count()).c_str());
	    
	    if (size > 0) {
	    	debug(90, "read: %d from syslog\n", size);
	    	return parseAndInsert(buf,size,fp,source,false);
	    }
	}
	//check for a line from files

	//call general purpose buffer fetcher
	size = fileHandler->getNextBuf(buf, &fp, &src);
	
	if(size==0) { 
		debug(112, "(%d) Empty string when reading log line (no files to read)\n",thNum);
		return false;
	}
	
	if(buf[0] == '#') {
		debug(85, "Header line read when reading log line\n");
		return true;
	}
	debug(94, "(%s) successfully read into buffer\n", 
		  boost::lexical_cast<std::string>(boost::this_thread::get_id()).c_str());
	debug(94, "buffer: \'%s\'\n",buf);

	return parseAndInsert(buf,size,fp,fileHandler->getCurSource(),true);

}

/*
 *  parseAndInsert() functions
 *   Accepts a buffer with a complete log line, null terminated
 *   Parses the line for the parts we care about.
 *   Inserts the line into toku DB.
 *
 *    returns true if nothing goes wrong
 *	
 */

bool InsertThread::parseAndInsert(char *buf,const int size, logFormat *fp, uint8_t source, bool fromFile) {
	std::list<logEntry*>results;
	int entries = src->parseBuf(buf, size, &fp, &results);
	// add to map that keeps track of insertions for each file
	if(fromFile) {
		std::string file = fileHandler->curFileKey();
		if (file_counts.count(file) == 0) {
			file_counts[file] = entries;
		}
		else {
			file_counts[file] += entries;
		}
	}
	bool no_failures = true;
	for(int i = 0; i < entries; i++) {
		// ewest - 09/10/18
		// Idea here is to differentiate between identical keys by passing a semi-unique number to createPair
		// The number is 8 bits (enforced by the function definition)
		// 			   00 : 000000 (number of bits each part gets based on shift and mask)
		//	Thread Number : Number of logs that thread has inserted
		// Note that this number can be used to encode whether or not the key is reversed if necessary
		// ((thNum << shift) + (numInserted & mask))
		
		KeyValuePair *pair = src->createPair(i, &results, source);
		if(!tokuHandler->put(pair))
			no_failures = false;
		numInserted += 1;
	}
	return no_failures;
}


/*
	Function for returning file status by querying filehandler

	ewest - 02/15/19
*/
std::vector<std::set<std::string>> InsertThread::fileStat() {
	return fileHandler->getFiles();
}

std::string InsertThread::getActiveFile() {
	return fileHandler->getActiveFile();
}

std::string InsertThread::fileInfo(std::string fileName) {
	return fileHandler->getFileInfo(fileName);
}

long InsertThread::fileCount(std::string fileName) {
	std::string fileKey = fileHandler->getKey(fileName);
	if (file_counts.count(fileKey) == 0 || fileKey == "ERROR") {
		return 0;
	}
	else {
		return file_counts[fileKey];
	}
}

std::string InsertThread::statsToFile(std::string fileName) {
	return fileHandler->statsToFile(fileName);
}

void InsertThread::statsFromFile(std::vector<std::string> data) {
	debug(30, "file key: %s\n", data[1].c_str());
	debug(30, "total file inserts: %s\n", data[5].c_str());
	file_counts[data[1]] = std::stol(data[5]);
	fileHandler->statsFromFile(data);
}

AbstractLog *InsertThread::getFormat(std::string format) {
	return fileHandler->getFormat(format);
}