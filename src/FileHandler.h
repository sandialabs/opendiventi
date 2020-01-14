/*
 * FileHandler is a thread-safe vector for ifstreams of BRO logs.
 */
#ifndef _FH_INCLUDE_GUARD
#define _FH_INCLUDE_GUARD
#include "diventi.h"

#include <deque>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <set>
#include <queue>

struct startOptions;
typedef struct startOptions startOptions;
struct logFormat;

class Watcher;
class DiventiStream;
class DiventiProcessed;

class Bro;
class NetV9;
class Basic;
class NetAscii;
class NetV5;
class Mon;

class file_data {
public:
	std::string key="no key";
    // Buffers is typically equivalent to lines read. 
    uint64_t buffers=0;
    uint64_t startTime=0; //keeps track of the most recent timestamp of ingesting this file
    uint64_t timeDone=0;	//Tracks the time at which we stopped interacting with this file(finished or paused) set to 0 when dealing with it
    uint64_t totalTime=0;

	inline bool file_changed() {
		return !(buffers_at_open == buffers);
	}
private:
	uint64_t buffers_at_open = 0; // how many buffers have we read when this file is opened
};

class Alpha_Compare {
public:
	bool operator() (std::pair<std::string,short> left, std::pair<std::string, short> right) {
		if( strcmp(left.first.c_str(), right.first.c_str()) < 0 ) {
			return true;
		}
		return false;
	}
};

class FileHandler{
	friend class Watcher;
public:
	FileHandler(std::vector<std::vector<std::string>> file_status);
	FileHandler();
	void readFileDir(std::string fileDir, short Source);
	AbstractLog *getFormat(std::string format);
	int watchDir(Watcher *watcher, std::string fileDir);
	int unwatchDir(Watcher *watcher, std::string fileDir);
	std::vector<std::set<std::string>> getFiles();
	std::string getActiveFile();
	std::string getFileInfo(std::string file);
	std::string getFileName();
	std::string curFileKey();
	std::string getKey(std::string file);

	ushort getCurSource() {return curSource;}

	std::string statsToFile(std::string file);
	void statsFromFile(std::vector<std::string> data);

	~FileHandler();

	std::string* getNextLine(logFormat **f);

	int getNextBuf(char * buf, logFormat **f, AbstractLog **src);

private:
	void queueFile(std::string path, short Source);
	
	void handleDir(std::string dir, short Source);
	void handleFile(std::string file, short Source);
        void processFileTimes(file_data * file_d);

	int setActiveStream();

	bool isValidFile(std::string file, short Source);
	
	DiventiStream* stream;
	DiventiProcessed* processed;

	AbstractLog *curFormat;

	ushort curSource = 1;

	std::mutex* mWaiting;
	std::mutex* mNextLine;

	// create a priority queue and a set of all elements within the priority queue
        // First argument to priority queue is definition of element type, second is the vector to hold
		// and third is the custom comparer to use when ordering elements
		//
		// The elements are a pair with the full file name and the number of the source associated with the file
		//
        // waiting_files is a
		// set of all the files that are waiting. As such, there are no duplicates.
		// There may be duplicates within waiting, however, given new code, waiting_files may be redundant
        //  
	std::priority_queue<std::pair<std::string, short>, std::vector<std::pair<std::string, short>>, Alpha_Compare>* waiting;
	std::set<std::string>* waiting_files;

	logFormat *parser;

	Watcher **watchers;

	std::set<std::string> files_popped;

	std::string curFile_key = "";

        // Keep track of the last file we were reading.
        // when moving to the next it is possible the same file
        // we just finished could be back in the priority queue
        // if so skip over it unless there are no other files waiting.
        std::string last_file_read="";

	//file_name -> file_data(file_key, buffers, startTime, timeDone, totalTime)
	std::unordered_map<std::string,file_data> file_lines;

	// pointers for each logFormat, which we will return along with buffers
	Bro *Bro_src;
	Mon *Mon_src;
	NetAscii *NetAscii_src;
	NetV5 *NetV5_src;
	NetV9 *NetV9_src;
	Basic *Basic_src;
};

#endif
