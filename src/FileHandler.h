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
	std::string key="";
    // Buffers is typically equivalent to lines read. 
    uint64_t buffers=0;
    uint64_t startTime=0; //keeps track of the most recent timestamp of ingesting this file
    uint64_t timeDone=0;	//Tracks the time at which we stopped interacting with this file(finished or paused) set to 0 when dealing with it
    uint64_t totalTime=0;

	file_data(){}
	// constructor for the first time we see a file
	file_data(std::string _key, uint64_t _startTime) {
		key = _key;
		startTime = _startTime;
	}
	// constructor for when we're pulling information about a file from the db
	file_data(std::string _key, uint64_t _buffers, uint64_t _timeDone, uint64_t _totalTime) {
		key = _key;
		buffers = _buffers;
		buffers_at_open = _buffers;
		timeDone = _timeDone;
		totalTime= _totalTime;
	}
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
	FileHandler(startOptions options);
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

	int setActiveStream();

	bool isValidFile(std::string file, short Source);
	
	DiventiStream* stream;
	DiventiProcessed* processed;

	AbstractLog *curFormat;

	ushort curSource = 1;

	std::mutex* mWaiting;
	std::mutex* mNextLine;

	// create a priority queue and a set of all elements within the priority queue
	std::priority_queue<std::pair<std::string, short>, std::vector<std::pair<std::string, short>>, Alpha_Compare>* waiting;
	std::set<std::string>* waiting_files;

	logFormat *format;

	Watcher **watchers;

	std::set<std::string> files_popped;

	std::string curFile_key = "";

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
