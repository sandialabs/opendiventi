#include "Watcher.h"
#include "FileHandler.h"
#include "diventi.h"

#include "sys/types.h"
#include "sys/stat.h"
#include <sys/inotify.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <regex>

#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/thread/thread.hpp>

/*
 * Standard constructor. Sets up an idle watcher.
 */
Watcher::Watcher(FileHandler& fh, short source) : fh(fh){
	inotifyfd = inotify_init();
	watchList = new std::vector<std::string>();
	revWatchList = new std::unordered_map<std::string, int>();
	mWatch = new std::mutex();
	numWatching = 0;
	active = false;

	Source = source;

	// Open and cnfigure a pipe for later interruption of watcher thread
	if (pipe(pipefds) == -1){
		debug(0, "Error setting up watcher: no pipe\n");
	}
	int flags = fcntl(pipefds[0], F_GETFL, 0);
	if(fcntl(pipefds[0], F_SETFL, flags | O_NONBLOCK)){
		debug(10, "Error setting up watcher: pipe is blocking.");
	}
}

/*
 * Sets up a watcher and immediately begins watching a directory.
 */
Watcher::Watcher(FileHandler& fh, std::string dir, short source) : fh(fh){
	inotifyfd = inotify_init();
	watchList = new std::vector<std::string>();
	revWatchList = new std::unordered_map<std::string, int>();
	mWatch = new std::mutex();
	numWatching = 0;
	active = false;

	Source = source;

	// Open and configure a pipe for later interruption of watcher thread
	if (pipe(pipefds) == -1){
		debug(0, "Error setting up watcher: no pipe\n");
	}
	int flags = fcntl(pipefds[0], F_GETFL, 0);
	if(fcntl(pipefds[0], F_SETFL, flags | O_NONBLOCK)){
		debug(10, "Error setting up watcher: pipe is blocking.");
	}

	watchDir(dir);
}

Watcher::~Watcher(){
	debug(10, "Destroying watcher...\n");
	cleanupWatcher(false);
	delete watchList;
	delete revWatchList;
	delete mWatch;
	close(pipefds[0]);
	close(pipefds[1]);
	close(inotifyfd);
	debug(10, "Watcher destroyed\n");
}

/*
 * Provides a safe way to shut down the watcher thread.
 * Can be run synchronously or asynchronously.
 */
void Watcher::cleanupWatcher(bool asynch){
	if (active){
		// Send an interrupt to the watcher thread
		char asdf[5] = "asdf";
		write(pipefds[1], asdf, 4);
		watcher->interrupt();

		// Clear the watch variables
		mWatch->lock();
		numWatching = 0;
		active = false;
		mWatch->unlock();

		if (asynch){
			// If asynch, detach the thread and move on
			watcher->detach();
		} else{
			// Otherwise, wait for it to halt
			watcher->join();
		}

		// Deleting watcher is not dangerous even if the detached watcher thread is still running
		delete watcher;
	}
}

/*
 * Checks the internal table to determine the watch descriptor for a directory.
 * Returns -1 if the file is not in the table or if an error occurred.
 */
int Watcher::getWD(std::string path){
	int wd = -1;

	mWatch->lock();
	try{
		wd = revWatchList->at(path);
	} catch(...){}
	mWatch->unlock();

	return wd;
}

/*
 * Attempts to watch a directory
 */
int Watcher::watchDir(std::string dir) {
	// First, check if the directory is already being watched
	if (getWD(dir) != -1){
		debug(10, "Error watching %s: already being watched\n", dir.c_str());
		return -1;
	}

	int ret = 0;

	// Check if it really is a directory
	struct stat path_stat;

    stat(dir.c_str(), &path_stat);
    bool isDir = S_ISDIR(path_stat.st_mode);
    int wd;
    char *err;

    if(isDir) {
    	// Subscribe to directory
    	wd = inotify_add_watch(inotifyfd, dir.c_str(), IN_CREATE | IN_MOVED_TO | IN_MODIFY);

    	// Be verbose on failure
    	if (wd == -1){
    		char errStr[256];
			err = strerror_r(errno, errStr, 256);
			err = err;
			// This error is often fixed by increasing the number of files inotify can handle
    		debug(10, "Error watching directory '%s': %s\n", dir.c_str(), errStr);
    		ret = -1;
    	} else{

    		mWatch->lock();
	    	// Track number of watched files
	    	numWatching += 1;
	    	// Add new watchee to lookup tables
	    	watchList->push_back(dir);
	    	(*revWatchList)[dir] = wd;

	    	// If the watcher thread is not currently active, activate it
	    	if (!active){
	    		active = true;
				watcher = new boost::thread(boost::bind(&Watcher::watch, this));
			}
			mWatch->unlock();
	   
	    	debug(10, "Now watching directory: %s\n", dir.c_str());

	    	// Iterate into subdirs and watch those too
	    	boost::filesystem::directory_iterator end_itr; // Default construction starts at the end
			for(boost::filesystem::directory_iterator itr(dir); itr != end_itr; ++itr) {
				
				std::string path = itr->path().string();
	    		stat(path.c_str(), &path_stat);
	    		isDir = S_ISDIR(path_stat.st_mode);
	    		if(isDir) {
					watchDir(path);
	    		}

			}

		}
	} else{
		debug(10, "Error: '%s' is not a directory\n", dir.c_str());
		ret = -1;
	}

	return ret;
}

/*
 * The watcher thread loop. Continuously watches for inotify events.
 * Can be interrupted by sending any message down the pipe
 */
void Watcher::watch(){
	char buf[sizeof(struct inotify_event) + NAME_MAX + 1];
	int len;
	char* ptr = buf;
	struct inotify_event* event;
	int selectResult;
	int greatestfd = (inotifyfd > pipefds[0]) ? inotifyfd : pipefds[0];

	fd_set fds;

	while(active){
		// If fds is not reset every time after select, undefined behavior will occur
		FD_ZERO(&fds);
		FD_SET(inotifyfd, &fds);
		FD_SET(pipefds[0], &fds);

		// Block until either there is a termination msg in the pipe or an inotify event occurs
		debug(70, "Blocking on read...\n");
		selectResult = select(greatestfd + 1, &fds, NULL, NULL, NULL);

		if (selectResult == -1){
			debug(1, "Error reading events\n");
		} else if (selectResult == 2){
			// Received both termination and new event; follow termination
			debug(40, "Watcher thread received termination notice while blocked.\n");
			break;
		} else{
			// One of the two was read: try to read termination; if it fails, continue, if success: terminate
			debug(70, "Checking for termination notice in Watcher::watch\n");
			len = read(pipefds[0], buf, 5);
			if (len > 0){
				debug(40, "Watcher thread received termination notice while blocked.\n");
				break;
			}
		}

		// Read the inotify event
		len = read(inotifyfd, buf, sizeof buf);

		// Loop through all events read (only whole events will be read)
		for (ptr = buf; ptr < buf + len; ptr += sizeof(struct inotify_event) + event->len){
			event = (struct inotify_event*) ptr;
			handleFileSystemEvent(event);
		}

		debug(99, "Watcher about to loop again\n");
		boost::this_thread::interruption_point();

		//  File system events are triggering constanly for the active file.
		//  This sleep will temper the rate at which we get events.
		boost::this_thread::sleep_for(boost::chrono::seconds(1));
	}
}

/*
 * Determines what the event was, where it was, and takes appropriate action.
 */
void Watcher::handleFileSystemEvent(struct inotify_event* event){
	// Get the path from the watchList in a thread-safe manner
	mWatch->lock();
	std::string path = (*watchList)[event->wd - 1] + "/" + event->name;
	mWatch->unlock();

	// Identify what type of path it is
	struct stat path_stat;
	stat(path.c_str(), &path_stat);
	bool isDir = S_ISDIR(path_stat.st_mode);

	if(isDir){
		debug(10, "Watcher found directory %s\n", path.c_str());
		// Add new directories to watch list
		watchDir(path);

	} else{
		debug(60, "Watcher found file %s\n", path.c_str());

		// Add new files to queue in Filehandler
		fh.handleFile(path, Source);
	}
}

/*
 * Stops watching a directory.
 * Returns 0 if successful, -1 otherwise.
 */
int Watcher::unwatchDir(std::string fileDir){
	// If nothing is being watched, don't bother.
	if (numWatching < 1){
		debug(10, "Error unwatching %s: numWatching < 1", fileDir.c_str());
		return -1;
	}

	// Get the watch descriptor (if that fails, abort)
	int wd = getWD(fileDir);
	if (wd == -1){
		debug(10, "Error unwatching %s: not in table", fileDir.c_str());
		return -1;
	}

	// Remove the path from the inotify watch subscription
	int rmStatus = inotify_rm_watch(inotifyfd, wd);
	if (rmStatus != 0){
		debug(10, "Error unwatching %s: not previously watching", fileDir.c_str());
		return -1;
	}

	mWatch->lock();
	numWatching -= 1;
	// Save memory by deleting records from lookup tables
	// Still need the vector to retain its placeholder, however
	revWatchList->erase(fileDir);
	mWatch->unlock();

	// Recursively unwatch all subdirectories
	boost::filesystem::directory_iterator end_itr; //Default construction starts at the end
	for(boost::filesystem::directory_iterator itr(fileDir); itr != end_itr; ++itr) {
		
		std::string path = itr->path().string();
		struct stat path_stat;
		stat(path.c_str(), &path_stat);
		bool isDir = S_ISDIR(path_stat.st_mode);
		if(isDir) {
			unwatchDir(fileDir);
		}
	}

	//if watcher is no longer needed, delete it cleanly
	if (numWatching < 1){
		cleanupWatcher(true);
	}

	return 0;
}
