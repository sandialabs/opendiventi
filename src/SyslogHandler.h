/* 
 * A thread-safe interface for retrieving log lines received
 * over UDP.
 */

#ifndef _UDPH_INCLUDE_GUARD
#define _UDPH_INCLUDE_GUARD

#include <mutex>

class AbstractLog;

struct source;

struct startoptions;
typedef struct startOptions startOptions;
struct logFormat;
typedef struct logFormat logFormat;

class SyslogHandler{
public:
	friend class SyslogHandlerHandler;
	SyslogHandler(source *src, uint8_t source_id);
	~SyslogHandler();

	unsigned int getNextLine(char * buf, const unsigned int maxSize, logFormat **f);
	unsigned int getNextBytes(char * buf, const unsigned int size, logFormat **f);
	unsigned long getNumDropped();
	unsigned int getNextPacket(char *buf, const unsigned int maxSize);
	void clearBuffer();

	AbstractLog *getFormat() { return format; }
	// void verifyData();
private:
	int readSocket();

	int sock;
	logFormat *cur_format;
	std::mutex m;  // mutex for handling read buffer

	// buffer and counters to make implement a circular buffer.


	char *rcvBuf;  // a large buffer where udp receive data will be stored.
	unsigned int nextData; // next data element to be processed

	AbstractLog *format;
	uint8_t source_id;

	// End of data never wraps and always shows valid last item in buffer
	// before we started from the front again. 
	//   This is not used to see if cur has no more data but ONLY used
	//   to indicate when to wrap.  Use nextEmpty to know when data is exhausted.
	// 
	//   note: endData is a valid slot with data. (handle +/-1 carefully)
	//   
	unsigned int endData; // end of good data (usually == next empty - 1)

	// Next empty is the next slot available to write into.
	// if nextEmpty < endData then we are wrapped.  Otherwise
	// nextEmpty should equal endData+1.
	unsigned int nextEmpty; // next spot that is ready to be written.	
};

// Handles syslog handlers
class SyslogHandlerHandler{
public:
	SyslogHandlerHandler(SyslogHandler **, int);
	~SyslogHandlerHandler(){};

	unsigned int getData(char * buf, logFormat **f, AbstractLog **src, uint8_t *source);

private:
	SyslogHandler **slhs;
	int num_handlers = 0;
	int cur_handler = 0;
};

#endif // _UDPH_INCLUDE_GUARD
