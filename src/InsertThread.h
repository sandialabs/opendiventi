#ifndef INSERTTHREAD_INCLUDED_DIVENTI
#define INSERTTHREAD_INCLUDED_DIVENTI


class FileHandler;
class TokuHandler;
class SyslogHandlerHandler;
class SyslogHandler;
class AbstractLog;
#include <vector>
#include <string>
#include <set>
#include <unordered_map> 

namespace boost {
	class thread;
}

struct logFormat;
struct logEntry;
typedef struct logFormat logFormat;



/*
	This thread parses logs, gets lines from FileHandler, 
	turns those lines into KeyValuePairs,
	and then initiates their insertion into ft-index through a TokuHandler.
*/

class InsertThread {
public:
	InsertThread(TokuHandler *handler, FileHandler *Fh, 
				 SyslogHandlerHandler *slh, int thNum);
	~InsertThread();
	void run();
	void thread();
        void interupt_n_join();
	std::vector<std::set<std::string>> fileStat();
	std::string getActiveFile();
	std::string fileInfo(std::string fileName);
	
	AbstractLog *getFormat(std::string format);
	
	// Function to return the total inserts done by this thread
	long fileCount(std::string fileName);

	std::string statsToFile(std::string fileName);
	void statsFromFile(std::vector<std::string> data);

	long long getNumInserted(){ return numInserted; }
	int thNum; // A simple number to index the thread.
	int shift;
	int mask;
        bool shutdown;  // a boolean to signal we have been told to shutdown.
        
private:
	boost::thread *t;
	bool readLog();
	bool parseAndInsert(char *buf,const int size, logFormat *fp, uint8_t source, bool fromFile);
	TokuHandler *tokuHandler;
	FileHandler *fileHandler;
	SyslogHandlerHandler *slhh;
	boost::thread *cli;

	//When logFormat and AbstractLog are combined, remove this
	AbstractLog *src;

	// Local counter for total number of inserts done by this thread.
	// file key -> count
	std::unordered_map<std::string, long> file_counts;

	long long numInserted = 0;
        

};

#endif
