/*
 *  A handler object that reads syslog data from a udp port and
 *  returns log file lines.
 *
 */


#include "SyslogHandler.h"
#include "diventi.h"

// #include "Bro_Parse.h"
// #include "Basic_Parse.h"
// #include "NetV9_Parse.h"
// #include "Net_Parse.h"
// #include "Mon_Parse.h"

#include "bro_functions.h"
#include "Basic_functions.h"
#include "NetV9_functions.h"
#include "netAscii_functions.h"
#include "NetV5_functions.h"
#include "Mon_functions.h"

#include <errno.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <boost/regex.hpp>

/**
Function to create the logFormat which syslogHandler uses to grab data from the buffer
The argument subFormat includes information specific to the format that tells logFormat
	about the data it's going to be recieving

For example - in mon this subFormat will be if mon is recieving tcp, udp, or icmp data

ewest - 03/27/19
**/
// static logFormat *createFormat(std::string subFormat, std::string format) {
// 	if( format == "bro" ){
// 		return new BroFormat(subFormat);
// 	}
// 	else if( format == "basic" ){
// 		return new BasicFormat(subFormat);
// 	}
// 	else if( format == "NetV5" ){
// 		return new NetFormat(subFormat);
// 	}
// 	else if( format == "net" ) {

// 	}
// 	else if( format == "v9" ){
// 		return new NetV9_Format();
// 	}
// 	else if( format == "mon" ){
// 		transProto p=UNKNOWN_TRANSPORT;
        
//         if ( subFormat == "tcp" ){
//                 p=TCP;
//         }
//         if ( subFormat == "udp" ){
//                 p=UDP;
//         }
//         if ( subFormat == "icmp" ){
//                 p=ICMP;
//         }
// 		return new MonFormat(p);
// 	}
// 	else{
// 		//defualt to bro format
// 		return new BroFormat(subFormat);
// 	}
// }

static AbstractLog *getLogFormat(std::string format) {
	if (format == "bro")
		return new Bro();
	else if (format == "basic")
		return new Basic();
	else if (format == "NetV5")
		return new NetV5();
	else if (format == "netAscii")
		return new NetAscii();
	else if (format == "NetV9")
		return new NetV9();
	else if (format == "mon")
		return new Mon();
	else 
		return new Bro();
}

SyslogHandler::SyslogHandler(source *src, uint8_t source_id){
	// Prepare UDP socket
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0){
		debug(1, "Could not create socket\n");
	}

	// Begin listening on port
	struct sockaddr_in addr;
	memset((char*)&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(src->syslogPort);
	if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0){
		debug(1, "Bind to port %d failed\n", src->syslogPort);
	}

	// Set up the parsing format that was loaded from the config.
	format = getLogFormat(src->logFormat);
	cur_format = format->createFormat(src->syslogArgs);
	this->source_id = source_id;
	
	// allocate receive buffer and initialze pointers.
	rcvBuf = new char[OPTIONS.syslogBufsize];
	nextData=0;
	nextEmpty=0;
	endData=-1; 

	debug(19,"Syslog Handler setup on port %d, offset:%d Bufsize:%ld\n",
		  src->syslogPort,OPTIONS.syslogOffset,OPTIONS.syslogBufsize);
}

SyslogHandler::~SyslogHandler(){
	if (sock != -1){
		close(sock);
	}
	delete[] rcvBuf;
	delete cur_format;
	delete format;
}

void SyslogHandler::clearBuffer() {
	m.lock();
	debug(5, "flushing udp buffer completely\n");
	delete[] rcvBuf;
	rcvBuf = new char[OPTIONS.syslogBufsize];
	nextData=0;
	nextEmpty=0;
	endData=-1;
	m.unlock();
}

/*
 *   Look in the udp buffer. Find the next complete line 
 *   and copy that into the buffer provided. add a null terminator
 *   then return the size of the line copied.
 *   
 *   A large circular buffer is used to store data received from the udp socket
 *   this is processed sequentially until the end of data is less than MAX_LINE
 *   from the end of the buffer.  Then we start using the front of the buffer again.
 *   Data is only read into the buffer when there is not a line of data available.
 *   We don't anticipate reads to be greater than 9000 (a jumbo MTU) -- famous last words...
 *
 *     NB: null terminate log lines.
 *
 *  returns: 0 for no line and otherwise the number of bytes in the line.
 *
 */
unsigned int SyslogHandler::getNextLine(char * buf, const unsigned int maxSize, logFormat **f){

	// unsigned int endOfLine=0;
	unsigned int cur;   // current pointer
	unsigned int s=0;   // the size of the line


	// TODO - check for empty and call read?
	//   - is that the common case?
	// TODO consider moving # into this routine.

	// Assign format to the one for syslog
	// TODO make this go away.
	*f = cur_format;

	// lock syslog-bufferg.
	m.lock();

	// If buffer is empty call read.
	if (nextData==nextEmpty) {
		s = readSocket();
		if (s==0) {
			m.unlock();
			return 0;
		}
		debug(110,"\n\nSyslog: found empty buffer, read %d\n  Buf: nd:%d nE:%d  eDL:%d\n",
		  s,nextData,nextEmpty, endData);
	}

	/*
	 *        look for next EOL
	 */ 
 findEol:
	cur = nextData;
	bool wrapped = false;
	while (rcvBuf[cur]!='\n') {
		cur++;
		// If we have more data keep going
		//  The common case is first test and just loops here.
		if (cur<=endData && !wrapped)
			continue;

		// if we're out on this line but we've wrapped cycle to the front.
		if (nextEmpty < endData && !wrapped) {
			cur = 0;
			wrapped = true;
		}

		// We've ran through all the data (possibly with a wrap).
		if (cur >= nextEmpty) {
			//see if there's more data to get
			s = readSocket();
			if (s==0) {
				break; //if not break
			}
			
		}

	}

	// At this point 
	//    if cur == \n or we're at end of buffer -- then we found eol
	//    if cur != eol we need to read
	//  + wrapped will say if we went past end and need to handle that edge case.
	debug(110,"finished EOL, at %d\n buf data: nd:%d nE:%d  eDL:%d wrap: %d\n",
		  cur,nextData,nextEmpty, endData, wrapped);

	// found a line - either \n or end of udp buffer.
	if (rcvBuf[cur]=='\n' || cur >= nextEmpty) {
		if (!wrapped) {
			debug(60, "not wrapped, cur: %u\n", cur);
			if( cur >= nextData ) {
				s = cur-nextData; // don't include \n in the line sent.
			}
			else {
				s = (endData - nextData) + cur;
			}
			if (s > maxSize) {
				// If the next line is greater than the max just truncate. 
				debug(25,"Warn: log line (%d) larger that buf size %d\n",s, maxSize);
				s=maxSize;
			}
			if (s>(unsigned int) OPTIONS.syslogOffset) {
				// copy the line
				s -= OPTIONS.syslogOffset;
				memcpy(buf,&rcvBuf[nextData+OPTIONS.syslogOffset],s);
				buf[s]=0;
			} else {
				debug(10,"log line %d smaller than offset %d\n",s,
					  OPTIONS.syslogOffset);
				s=0;
			}
			debug(70, "s: %u size: %d\n", s, (int)strlen(buf));
			nextData = cur; 
			if (rcvBuf[cur]=='\n' )  // move past \n  if there was one.
				nextData+=1;
		}
		else {  // We wrapped
			debug(60, "wrapped, cur: %u end: %u next: %u\n", cur, endData, nextData);
			s=(endData - nextData) +1; // calculate the data left at the end
			if (nextData > endData) {
				//Catch case where we wrap and end of last buffer
				//was directly at end of syslogBuffer
				s = 0;
			}
			// copy the tail first
			memcpy(buf,&rcvBuf[nextData],s);
			// copy the part from the front of the buffer
			memcpy(buf+s,rcvBuf,cur); // cur = \n and we're not copying that so no +1.
			s += cur;

			//  Handle the offset clipping.
			//    and shift the new memory in the caller's buf.
			s -= OPTIONS.syslogOffset;
			memmove(buf,buf+OPTIONS.syslogOffset,s);
			
			buf[s]=0;
			debug(70, "s: %u size: %d\n", s, (int)strlen(buf));
			// reset the points for the wrap
			if (rcvBuf[cur]=='\n')
				nextData=cur+1;
			else
				nextData=nextEmpty;
			endData = nextEmpty -1;
		}
		
#if 0  // an optimization -- while testing we leave it out.
		// if buffer is empty reset to 0.
		if (nextEmpty==nextData) {
			nextEmpty=0;
			nextData=0;
			endData=-1;
		}
#endif

		// If it doesn't begin with a comment return it
		//   otherwise continue to look for another line.
		if (buf[0]!='#') {
			m.unlock();
			debug(150,"returning line of %d\n\t\'%s\'\n Buf data: nd:%d nE:%d  eDL:%d \n",
				  s,buf,nextData,nextEmpty, endData);
			return s;
		}
		debug(20,"Skipping comment line %d\n\t\'%s\'\n Buf data: nd:%d nE:%d  eDL:%d \n",
			  s,buf,nextData,nextEmpty, endData);
	}


	// At this point we didn't find a complete line. 
	//  try reading --
	//     if we get data process again
	//     else no data return 0.
	s = readSocket();
	if (s!=0)
		goto findEol;  // TODO find a better way or enjoy irratating purists (TB).

	m.unlock();
	return 0;
}

/* 
 *  readSocket 
 *   reads data from the socket and fills up the buffer.
 *   returns the amount of data read.
 *
 *    NB: this func assumes you have lock.
 */
int SyslogHandler::readSocket() {
	
	int len;
	ssize_t r;
	ssize_t total=0;
	// read at least syslog offset +2
	while (total < OPTIONS.syslogOffset+2) {
		len = OPTIONS.syslogBufsize - nextEmpty;
		
		// recv fails with EAGAIN/EWOULDBLOCK if queue empty
		r = recv(sock, rcvBuf+nextEmpty, len, MSG_DONTWAIT);
		debug(110,"socket returned %ld\n",r);

		if (r==-1) {
			if (errno != EWOULDBLOCK)
				perror("Got Error on syslog reading");
			return 0;
		}
		total+= r;
	}
	
	nextEmpty += r;
	endData +=r;
	if(endData > nextEmpty) { //should only occur if wrapped
		endData -= r; //Because if we're wrapped this data didn't go at the end
	}
	// do we need to wrap nextEmpty?
	if (nextEmpty+MAX_LINE > OPTIONS.syslogBufsize)
		nextEmpty = 0;

	return r;
}

// //Find the starting point for binary data
// void SyslogHandler::verifyData() {
// 	m.lock();
// 	while(true) {
// 		//if found start of data or exhausted all data
// 		debug(0, "nextData: %u\n", nextData);
// 		if((rcvBuf[nextData] == 5 && rcvBuf[60] == 0 && rcvBuf[70] == 0) || nextData==nextEmpty) {
// 			m.unlock();
// 			return;
// 		}
// 		else //seek
// 			nextData += 1;
// 	}
// }

//Function for reading a specified number of bytes from the udp buffer
unsigned int SyslogHandler::getNextBytes(char * buf, const unsigned int size, logFormat **f){

	//unsigned int cur;   // current pointer
	unsigned int s=0;   // the size of the buffer


	// TODO - check for empty and call read?
	//   - is that the common case?
	// TODO consider moving # into this routine.

	// Assign format to the one for syslog
	// TODO make this go away.
	*f = cur_format;

	// lock syslog-bufferg.
	m.lock();

	// If buffer is empty call read.
	if (nextData==nextEmpty) {
		s = readSocket();
		if (s==0) {
			m.unlock();
			return 0;
		}
		debug(110,"\n\nSyslog: found empty buffer, read %d\n  Buf: nD:%d nE:%d  eDL:%d\n",
		  s,nextData,nextEmpty, endData);
	}
	bool reading = true;
	while (reading) {
		bool wrapped = false;
		if(nextEmpty < endData)
			wrapped = true;
		//Verify that there are enough available bytes... if so grab them
		if( (endData - nextData) + 1 >= size ) {
			memcpy(buf, &rcvBuf[nextData], size);
			nextData += size;
			
			m.unlock();
			return size;
		}
		//If we're wrapped then check the end of the buffer and the beginning
		//	in case there aren't enough bytes at the end
		else if( wrapped && (endData - nextData) + nextEmpty + 1 >= size ) {
			int endSize = (endData - nextData) + 1;
			//copy from the end of the buffer
			memcpy(buf, &rcvBuf[nextData], endSize);
			//copy from the beginning of the buffer
			memcpy(buf+endSize, rcvBuf, size - endSize);
	
			nextData = size - endSize;
			endData = nextEmpty - 1;
	
			m.unlock();
			return size;
		}
		else { //we didn't get enough data
			//check to see if there's more data to be read
			s = readSocket();
			if(s == 0) //there is no more data
				reading = false;
		}
	}
	m.unlock();
	return 0;
}

/*
ewest 2018-11
Function that reads in a packet from the socket

This function assumes that each read from the buffer generates one and only one packet
Rudimentary error checking for if more or less than a packet is grabbed should take place
	in whatever function calls this one

In practice we have observed that the one packet per read ratio holds (but error checking still needed)
*/

unsigned int SyslogHandler::getNextPacket(char * buf, const unsigned int maxSize) {
	m.lock();
	ssize_t r = recv(sock, buf, maxSize, MSG_DONTWAIT);
	m.unlock();
	if (r==-1) {
		if (errno != EWOULDBLOCK)
			perror("Got Error on syslog reading");
		return 0;
	}
	debug(70, "Size of packet read from udp: %u\n", (uint)r);
	return (uint)r;
}


/*
--------------------------------------------------------------------------
-----------------------    SyslogHandlerHandler    -----------------------
--------------------------------------------------------------------------

This is a class for handling syslogHandlers
It's purpose is to simplify the interface from insertionHandler to collect data
from one of many syslogHandlers.

The name will never be changed

04/10/19 - ewest */
SyslogHandlerHandler::SyslogHandlerHandler(SyslogHandler **_slhs, int _num_handlers) {
	slhs = _slhs;
	num_handlers = _num_handlers;
}

//function to get data from the set of syslogHandlers in round robin style
unsigned int SyslogHandlerHandler::getData(char * buf, logFormat **f, AbstractLog **src, uint8_t *source) {
	unsigned int size = 0;
	//check if this slh has data to give if not go to the next one, do this for each syslogHandler only once
	for(int i = 0; i < num_handlers; i++) {
		int handler = (cur_handler + i) % num_handlers;
		*src = slhs[handler]->getFormat();
		size = (*src)->getSyslogData(slhs[handler], buf, f);
		if (size > 0) { // We found data so stop looping
			cur_handler = (handler + 1) % num_handlers;
			*source = slhs[handler]->source_id;
			break;
		}
	}
	return size;
}
