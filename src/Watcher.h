#ifndef WATCHER_INCLUDED_DIVENTI
#define WATCHER_INCLUDED_DIVENTI

#include <mutex>
#include <deque>
#include <vector>

#include <unordered_map>
#include <unordered_set>

namespace boost {
	class thread;
}

class FileHandler;

class AbstractLog;


extern const std::string WORKING_DIR;
extern const std::string FINISHED_DIR;
extern const std::string FAILED_DIR;
extern const std::string OUT_OF_FILES;

class Watcher{
public:
	Watcher(FileHandler& fh, short Source);
	Watcher(FileHandler& fh, std::string dir, short Source);
	int watchDir(std::string fileDir);
	void readFileDir(std::string fileDir);
	int unwatchDir(std::string fileDir);
	~Watcher();
private:
	void cleanupWatcher(bool asynch);
	int getWD(std::string path); // returns wd if successfull, -1 if not
	void watch();
	void handleFileSystemEvent(struct inotify_event*);
	void handleFile(std::string file, std::string baseDir);
	FileHandler& fh;

	//pointer to set of functions which the files read from this watcher will need
	short Source;

	int inotifyfd;
	boost::thread* watcher;
	std::vector<std::string>* watchList;
	std::unordered_map<std::string, int>* revWatchList;
	volatile int numWatching;
	std::mutex* mWatch;
	int pipefds[2];
	volatile bool active;
};

#endif