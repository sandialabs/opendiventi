#include "FileHandler.h"
#include "diventi.h"
#include "Watcher.h"
#include "DiventiStream.h"
#include "DiventiProcessed.h"
#include "bro_functions.h"
#include "NetV5_functions.h"
#include "NetV9_functions.h"
#include "netAscii_functions.h"
#include "Basic_functions.h"
#include "Mon_functions.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <limits.h>
#include <unistd.h>
#include <regex>

#include <iostream>

#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/unordered_map.hpp>
#include <boost/thread/thread.hpp>
#include <boost/iostreams/filter/gzip.hpp>
// #include <boost/iostreams/filtering_stream->hpp>

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

#include <boost/serialization/unordered_map.hpp>
#include <boost/serialization/serialization.hpp>
#include <boost/chrono.hpp>

static uint64_t getTime() {
	auto now = std::chrono::system_clock::now();
	return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
}

static std::string formatTime(uint64_t ts) {
	char *buf = new char();
	time_t time = (time_t)ts;
	struct tm *timestruct;
	timestruct = localtime(&time);
	strftime(buf, 20, "%D at %R", timestruct);
	std::string ret = std::string(buf);
	delete buf;
	return ret;
}

AbstractLog *FileHandler::getFormat(std::string format) {
	//These determine how to get the data, parse it, insert it, and more
	
	debug(75, "Setting up format\n");
	
	if( format == "bro") {
		return Bro_src;
	}
	else if( format == "mon"){
		return Mon_src;
	}
	else if (format == "NetV5") {
		return NetV5_src;
	}
	else if (format == "NetV9"){
		return NetV9_src;
	}
	else if (format == "netAscii"){
		return NetAscii_src;
	}
	else if (format == "basic"){
		return Basic_src;
	}
	//NEWFORMAT Add new ifs for new formatting types here
	else {
		debug(1, "WARNING: Unrecognized logFormat %s, defaulting to bro\n", format.c_str());
		return Bro_src;
	}
}

FileHandler::FileHandler() {
	debug(10, "Creating FileHandler...\n");
	waiting = new std::priority_queue<std::pair<std::string, short>, std::vector<std::pair<std::string,short>>, Alpha_Compare>();
	waiting_files = new std::set<std::string>();
	mWaiting = new std::mutex();
	mNextLine = new std::mutex();
	stream = new DiventiStream();
	processed = new DiventiProcessed();
	parser = nullptr;

	// initialize source functions
	Bro_src 	 = new Bro();
	Mon_src		 = new Mon();
	NetAscii_src = new NetAscii();
	NetV5_src	 = new NetV5();
	NetV9_src	 = new NetV9();
	Basic_src	 = new Basic();

	// define the vector watchers to contain 256 pointers to Watcher
	watchers = new Watcher*[256];
	// define all to NULL
	for( int i = 0; i < 256; i++ ) {
		//if the inputDir was specified then create a watcher and perform setup
		if(OPTIONS.sources[i] == nullptr || OPTIONS.sources[i]->inputDir == "") {
			watchers[i] = NULL;
		}
		else {
			debug(60, "setup for source %d\n", i);
			watchers[i] = new Watcher(*this, i);
			readFileDir(OPTIONS.sources[i]->inputDir, i);
			if(OPTIONS.continuous){
				debug(50,"File Cont flag active\n");
				watchDir(watchers[i], OPTIONS.sources[i]->inputDir);
			}
		}
	}
}

FileHandler::FileHandler(std::vector<std::vector<std::string>> file_status) {
	debug(10, "Creating FileHandler...\n");
	waiting = new std::priority_queue<std::pair<std::string, short>, std::vector<std::pair<std::string,short>>, Alpha_Compare>();
	waiting_files = new std::set<std::string>();
	mWaiting = new std::mutex();
	mNextLine = new std::mutex();
	stream = new DiventiStream();
	processed = new DiventiProcessed();
	parser = nullptr;

	// initialize source functions
	Bro_src 	 = new Bro();
	Mon_src		 = new Mon();
	NetAscii_src = new NetAscii();
	NetV5_src	 = new NetV5();
	NetV9_src	 = new NetV9();
	Basic_src	 = new Basic();

	// pull file data out of file
	for( std::vector<std::string> tokens : file_status ) {
		statsFromFile(tokens);
	}

	// define the vector watchers to contain 256 pointers to Watcher
	watchers = new Watcher*[256];
	// define all to NULL
	for( int i = 0; i < 256; i++ ) {
		//if the inputDir was specified then create a watcher and perform setup
		if(OPTIONS.sources[i] == nullptr || OPTIONS.sources[i]->inputDir == "") {
			watchers[i] = NULL;
		}
		else {
			debug(60, "setup for source %d\n", i);
			watchers[i] = new Watcher(*this, i);
			readFileDir(OPTIONS.sources[i]->inputDir, i);
			if(OPTIONS.continuous){
				debug(50,"File Cont flag active\n");
				watchDir(watchers[i], OPTIONS.sources[i]->inputDir);
			}
		}
	}
}

FileHandler::~FileHandler() {
	debug(10, "Destroying FileHandler...\n");
	for( int i = 0; i < 256; i++) {
		if( watchers[i] != NULL ) {
			delete watchers[i];
		}
	}
	delete[] watchers;
	delete waiting;
	delete waiting_files;
	delete mWaiting;
	delete mNextLine;
	delete parser;

	//delete source functions
	delete Bro_src;
	delete Mon_src;
	delete NetAscii_src;
	delete NetV5_src;
	delete NetV9_src;
	delete Basic_src;

	// Write the last stream->getFileName() position to the processed table
	processed->setLastPos(curFile_key, stream->tellPos());
	delete processed;
	delete stream;
}


/*
 * Reads a line from a file and returns it. Thread safe.
 * If there are no files to read from, returns a nullptr.
 * Otherwise, guarantees a non-empty line.
 */
std::string* FileHandler::getNextLine(logFormat **f){
	std::string* ret = nullptr;
	int ec;
	mNextLine->lock();

	// Repeat while the line is invalid
	while (ret == nullptr || ret->length() < 1){
		if (ret != nullptr){
			delete ret;
			ret = nullptr;
		}
		// If no active file
		if (!stream->good()){
			// Attempt to open a file
			while ( (ec = setActiveStream()) == -1 ){
				debug(10, "Error opening file\n");
			}

			// If no more files, abort
			if (ec == 1){
				debug(80, "Out of files\n");
				break;
			}
		}

		debug(40, "Reading from file '%s'\n", stream->getFileName().c_str());
		ret = stream->getLine();

		if(ret->substr(0,1) == "#") {
			ret = nullptr; // skip headers
		}

		if (!stream->good()){
			debug(29, "File '%s' ended\n", stream->getFileName().c_str());//, setting last pos\n", stream->getFileName().c_str());
			file_data *file_d = &file_lines[stream->getFileName()];
			if(file_d->file_changed()) { //then we added data and should change the timestamps
                            processFileTimes(file_d);
			}
			processed->setLastPos(curFile_key, stream->tellPos());
		}
	}
	debug(50, "Read line %s\n", ret ? ("'" + *ret + "'").c_str() : "nullptr");
	// memcpy(f, &format, sizeof(logFormat));
	*f = parser;
	mNextLine->unlock();
	return ret;
}

/*
	Reads data from file and places it in buf. Returns the number of characters copied. Thread safe.
	Based on the setup in insertThread will either read a line from the file (for ascii) or 48
	bytes (for binary netflow)
	If there are no data to read from, returns a nullptr.
		ewest - 07/22/18
*/

int FileHandler::getNextBuf(char* buf, logFormat **f, AbstractLog **src){

	int ret=0;;
	int ec;
	
	mNextLine->lock();
	// Repeat while the line is invalid
	while (ret == 0) {

		// If no active file
		if (!stream->good()){
			// Attempt to open a file
			while ( (ec = setActiveStream()) == -1 ){
				debug(10, "Error opening file\n");
			}

			// If no more files, abort
			if (ec == 1){
				debug(80, "Out of files\n");
				break;
			}
		}

		debug(80, "Reading from file '%s'\n", stream->getFileName().c_str());
		ret = curFormat->getRawData(buf, stream);
		//Code to track the number of buffers read from a file
		//02/19/19 - ewest
		if (ret != 0) {
			file_lines[stream->getFileName()].buffers +=1;
		}

		if (!stream->good()){
			debug(29, "File '%s' ended\n", stream->getFileName().c_str());//, setting last pos\n", stream->getFileName().c_str());
                        last_file_read= stream->getFileName();
			file_data *file_d = &file_lines[stream->getFileName()];
			if(file_d->file_changed()) { //then we added data and should change the timestamps
                            processFileTimes(file_d);
 			}
			processed->setLastPos(curFile_key, stream->tellPos());
		}
	}
	mNextLine->unlock();

	debug(85, "Read buffer(%d) \'%s\'\n", ret, buf);
	*f = parser;
	*src = curFormat;

	return ret;
}

/*
 * Reads a directory or attempts to add a file to the waiting queue.
 */
void FileHandler::readFileDir(std::string fileDir, short source) {
	// Check if the passed value is a valid filesystem path
	boost::filesystem::path p(fileDir);
	boost::system::error_code ec;
	if (!boost::filesystem::exists(p, ec) || ec){
		debug(10, "Error: %s does not exist.\n", fileDir.c_str());
		return;
	}

	// Check if the passed value is a file or directory
	struct stat path_stat;
    stat(fileDir.c_str(), &path_stat);
    bool isDir = S_ISDIR(path_stat.st_mode);

    // Handle it according to what it was
    if(isDir) {
    	handleDir(fileDir, source);
    } else {
    	handleFile(fileDir, source);
	}
}

/*
 * Tells the watcher to start watching a file or directory.
 * Returns 0 if successful, -1 otherwise.
 */
int FileHandler::watchDir(Watcher *watcher, std::string fileDir){
	return watcher->watchDir(fileDir);
}

/*
 * Tells the watcher to stop watching a file or directory.
 * Returns 0 if successful, -1 otherwise.
 */
int FileHandler::unwatchDir(Watcher *watcher, std::string fileDir){
	return watcher->unwatchDir(fileDir);
}

/*
 * Performs thread-safe insertion into the waiting queue.
 */
void FileHandler::queueFile(std::string path, short source) {
	mWaiting->lock();
	waiting->push(std::pair<std::string, short>(path, source));
	waiting_files->insert(path);
	mWaiting->unlock();
}

/*
 * Attempts to set the active stream.
 * Returns 0 on success, -1 on failure to open a file,
 * and -2 if there are no more files. 

 */
int FileHandler::setActiveStream() {
	int ret = 0;
	debug(124, "Attempting to set activeStream\n");

	mWaiting->lock();
	// Check if there is a file to read
	if(waiting->empty()) {
		debug(80, "Out of files to read.\n");
		mWaiting->unlock();
		return 1;
	}

	//----------
	//  The que isn't empty.... Let's open a file.
	//
	// Get the path to the next file to read
	std::string next = waiting->top().first;
	curSource = waiting->top().second;
	waiting->pop();


	// 
	// Check for the case that we are going through multiple files
	// the file at the top of the queue is the same one we just closed.
	//
	if (!waiting->empty() && next==last_file_read) {
		// If so skip to the next file and requeue this one
		// so we don't continually loop opening and ending the same
		// file while many other files wait.            
		std::string new_next = waiting->top().first;
		short new_Source = waiting->top().second;
		debug(47,"Skipping past top file %s because we just processed it. size:%ld \n ... opening %s\n",
			next.c_str(),  waiting->size(), new_next.c_str());            
		waiting->pop();
		waiting->push(std::pair<std::string, short>(next,curSource));
		next = new_next;
		curSource=new_Source;           
	}
                
	curFormat = getFormat(OPTIONS.sources[curSource]->logFormat);
        
	//remove the file from the set of waiting files if it's in there
	//this check is in case multiple files have the same name and it was removed earlier
	if ( waiting_files->count(next) != 0) {
		waiting_files->erase(next);
	}

        
	// Attempt to open it
        debug(45, "Attempting to open file '%s' (length %li)\n", next.c_str(), processed->getMaxPos(next));
	if (!stream->tryOpen(next)){
            debug(10, "Failed to open file: %s\n", next.c_str());
            mWaiting->unlock();
            return -1;
	}

        
	//--------
	// File opened successfully. setup the stream
	//
	// If successful, set trackers and current position
	debug(30, "Opened file '%s'\n", next.c_str());
	stream->getFileName() = next;


        
	std::string file_key = curFormat->getKey(next);
	debug(35, "file has key: %s\n", file_key.c_str());

	long pos = processed->getLastPos(file_key);
	stream->seekPos(pos);

	logFormat *old_parse = parser;

	if(!curFormat->parseFileFormat(stream->getFileName(), &parser)) {
		debug(45, "WARNING: Using default fields for file %s\n\n", next.c_str());
		parser = curFormat->createFormat(OPTIONS.sources[curSource]->defaultFields);
		stream->seekPos(pos); // didn't find fields so go back to where we started from
	}
	delete old_parse;

	//if we have no entry for this file name
	if (file_lines.count(next) == 0) {
		//scan through all files to see if key matches
		bool found = false;
		file_data temp;
		std::string oth_file;

		// This code was the part causing a std::alloc error, it should be fixed now
		// It was happening because the for loop would get to a item that had been deleted
		// and would try to run the code on it which didn't work
		for (std::pair<std::string, file_data> element : file_lines) {
			if (element.second.key == file_key) {
				found = true;
				//overwrite the old file name with the new file name
				temp = element.second;
				oth_file = element.first;
			}
		}
		if (found == true) {
			debug(40, "replacing file name %s with file name %s in file_lines\n", oth_file.c_str(), next.c_str());
			file_lines[next] = temp;
			file_lines[next].startTime = getTime();
			file_lines.erase(oth_file);
		}
		if (found == false) {
			file_data temp;
			temp.key = file_key;
			temp.startTime = getTime();
			file_lines[next] = temp;
		}
	}
	//if we do have a entry for this file name
	else {
		//check that the keys match and that stored key is not empty
		//if not give this file name a postscript ie 'file_name'_alt
		if( file_key != file_lines[next].key && file_key != "no key") {
			file_data temp;
			temp.key = file_key;
			temp.startTime = getTime();
			next += "_alt";
			stream->getFileName() = next;
			file_lines[next] = temp;
		} else {
			file_lines[next].startTime = getTime();
		}

	}        
	curFile_key = file_key;
	mWaiting->unlock();
	return ret;
}

/*
 * Reads a directory and handles subdirectories and files inside it.
 * Attempts to add discovered files to the waiting queue.
 */
void FileHandler::handleDir(std::string dir, short source) {
	debug(25, "handling dir: %s\n", dir.c_str());
	if(!boost::filesystem::exists(dir)) {
		debug(50, "handling dir that doesn't exist: %s\n", dir.c_str());
		return;
	}

	struct stat path_stat;
	boost::system::error_code ec;
	
	// Use the default construction to create a stopping point (default results in end)
	boost::filesystem::directory_iterator end_itr;
	// Iterate through all the files and subdirectories' files
	for(boost::filesystem::directory_iterator itr(dir); itr != end_itr; ++itr) {
		std::string path = itr->path().string();
    	stat(path.c_str(), &path_stat);
    	bool isDir = S_ISDIR(path_stat.st_mode);

    	if (ec){
    		debug(20, "Error scanning '%s': %s\n", path.c_str(), ec.message().c_str());
    	}

    	// Handle the discovered path according to its type
    	if(isDir) {
    		debug(90, "directory iterator arrived on a directory: %s\n", path.c_str());
    		handleDir(path, source);
    	} else {
    		debug(90, "directory iterator arrived on a file: %s\n", path.c_str());
    		handleFile(path, source);
    	}
	}
}

/*
 * Attempts to add a file to the waiting queue.
 * A file may be skipped over for the following reasons:
 * 	- The path/name does not match the name regex
 * 	- The file has no more characters to read and is not currently active (in the "current" directory)
 *
 *   2019-12 -- added logic to skip queing if the file is currently being processed
 *   
 */
void FileHandler::handleFile(std::string file, short source) {
	debug(80, "handling file: %s\n", file.c_str());

        // Check if this file is already in the list, if so just skip.
        if (waiting_files->find(file)!=waiting_files->end()) {
            debug(80, "skipping adding redundant file %s to wait list\n", file.c_str());
            return;
        }

        // If not a file we're tracking (criteria note above) then skip it 
	if (!isValidFile(file, source))
                return;
        
        // If we're currently reading it then don't re-add it to the queue
        // this gives a chance for other files to also be read if the most
        // recent file is continually being updated
        if (stream->good() && file==stream->getFileName()) {
                debug(53, "Skipping que of file %s\n",file.c_str());
                return;                
        }
        
        // All criteria were met -- que this file.
	queueFile(file, source);
	debug(40, "enqueued file '%s'\n", file.c_str());
	
}

/*
 * Checks if a file is valid. Validity is determined by the following criteria:
 *  - The path/name matches the regex, if there is one
 *  - The file has characters left to read or it is currently active (in the "current" directory)
 */
bool FileHandler::isValidFile(std::string file, short source){
	bool ret = false;
	boost::filesystem::path p(file);
	// If there is no file name regex to check or if the given path matches it
	try {
		if (OPTIONS.sources[source]->fNameFormat == "" || std::regex_match(p.filename().string(), std::regex(OPTIONS.sources[source]->fNameFormat.c_str()))){
			// get the format for the file
			AbstractLog *format = getFormat(OPTIONS.sources[source]->logFormat);
			// get the key of the file
			std::string key = format->getKey(file);
			// If there are characters left to read or the file is active, return true
			if (processed->charsLeft(file, key) != 0){
				ret = true;
			} else{
				debug(50, "File '%s' already processed.\n", file.c_str());
			}

		} else{
			debug(50, "File '%s' did not match regex '%s'\n", p.filename().string().c_str(), OPTIONS.sources[source]->fNameFormat.c_str());
		}
	} catch(std::regex_error) {
		diventi_error("Regex %s is malformed. Stopping\n", OPTIONS.sources[source]->fNameFormat.c_str());
		exit(EXIT_FAILURE);
	}
	

	return ret;
}

/*
	Return the files currently being processed and those that are waiting

	ewest - 02/14/19
*/
std::vector<std::set<std::string>> FileHandler::getFiles(){
	std::vector<std::set<std::string>> ret;

	std::set<std::string> files_popped;
	for (std::pair<std::string, file_data> element : file_lines) {
		files_popped.insert(element.first);
	}

	ret.push_back(files_popped);
	ret.push_back(*waiting_files);

	return ret;
}

/*
	Return the file that is currently being ingested by this fileHandler
	
	ewest - 03/14/19
*/
std::string FileHandler::getActiveFile() {
	if(stream->getFileName() != "") {
		if((unsigned long)stream->tellPos() == processed->getMaxPos(stream->getFileName())) {
			return "";
		}
	}
	return stream->getFileName();
}

/*
	Converts from a number (100000) to a string with commas ("100,000")

	ewest - 03/14/19
*/
static std::string num_to_str(uint64_t number) {
	std::string ret = std::to_string(number);

	uint offset = ret.size() % 3;
	if (offset != 0 && ret.size() > 3) {
		ret.insert(offset, ",");
		offset += 1;
	}

	for( uint i = offset + 3; i < ret.size(); i+=4) {
		ret.insert(i, ",");
	}
	return ret;
}

/*
	Used for returning the statistics of a specific file

	ewest - 02/16/19 updated 06/25/19 to not need the file to exist after it's read
*/
std::string FileHandler::getFileInfo(std::string file) {
	// boost::filesystem::path p(file);
	std::string key = file_lines[file].key;

	// check that we have an entry for this file
	if (file_lines.count(file) > 0){
		// grab timing data
		std::string timeDone  = (file_lines[file].timeDone == 0)? "no time data":formatTime(file_lines[file].timeDone/1000000000);
		std::string totalTime = (file_lines[file].totalTime == 0)? "no time data":std::to_string(((float)file_lines[file].totalTime)/1000000000.0);
		std::string startTime = (file_lines[file].startTime == 0)? "no time data":formatTime(file_lines[file].startTime/1000000000);
		
		// if this is the currently active file
		if (file == stream->getFileName() && (long int)processed->getLastPos(key) < stream->tellPos()){
			// if done
			if((unsigned long)stream->tellPos() == processed->getMaxPos(file)){
				return "DONE(byte position: " + num_to_str(stream->tellPos()) + "; buffers read: " + num_to_str(file_lines[file].buffers) \
				+ "; time to ingest(sec): " +totalTime+ "; processed on: " + timeDone;
			}
			// if not done
			else {
				return std::to_string((int)(((double)stream->tellPos() / (double)processed->getMaxPos(file)) * 100 )) \
				+ "%(byte position: " + num_to_str(stream->tellPos()) + "; buffers read: " + num_to_str(file_lines[file].buffers) + \
				"; started ingesting on: " + startTime;
			}
		}

		// if this is not the currently active file
		else {
			// Print done if max size == lastPos or if we don't know the max size because the file is gone(or error)
			// getMaxPos returns an unsigned long -1 if it can't find max size
			if (processed->getLastPos(key) == processed->getMaxPos(file) || processed->getMaxPos(file) == (unsigned long)-1){
				return "DONE(byte position: " + num_to_str(processed->getLastPos(key)) + "; buffers read: " + num_to_str(file_lines[file].buffers) \
				+ "; time to ingest(sec): " + totalTime + "; processed on: " + timeDone;
			}

			else {
				return std::to_string((int)(((double)processed->getLastPos(key) / (double)processed->getMaxPos(file)) * 100 )) \
				+ "%(byte position: " + num_to_str(processed->getLastPos(key)) + "; buffers read: " + num_to_str(file_lines[file].buffers) \
				+ "; started ingesting on: " + startTime;
			}
		}
	}

	else {
		return "bad file name";
	}
}

// A simple function to process the times and do a bunch of sanity checks.
void FileHandler::processFileTimes(file_data *file_d){
    uint64_t curTime = getTime();

    file_d->timeDone = curTime;
    
    // Do some sanity checks
    if (file_d->startTime==0 || file_d->startTime > curTime) {
        debug(10,"WARNING file: %s has invalid start time %ld (cur: %ld).\n",
              file_d->key.c_str(), file_d->startTime, curTime);
        // removed totalTime to zero because we may already have a total time for this file. No reason to wipe it out
        return;
    }
    file_d->totalTime += curTime - file_d->startTime;
}

// function to return the statistics on a particular file for storing in tokudb.inserts
std::string FileHandler::statsToFile(std::string file) {
	file_data *file_d = &file_lines[file];
	if(file_d->file_changed()) { //then we added data and should change the timestamps
            processFileTimes(file_d);
	}
	return file_lines[file].key + ";" + std::to_string(file_lines[file].buffers) + ";"+ std::to_string(file_lines[file].timeDone) +";" +std::to_string(file_lines[file].totalTime);
}

//function to take file statistics read from tokudb.inserts and store it in our datastructure
void FileHandler::statsFromFile(std::vector<std::string> data) {
        bool corrupt=false;

	debug(30, "file buffers: %s\n", data[2].c_str());
	debug(30, "file timeDone: %s\n", data[3].c_str());
	debug(30, "file totalTime: %s\n", data[4].c_str());
	file_data temp;
	temp.key       = data[1];
        try {
            temp.buffers   = std::stol(data[2]);
        }
        catch (...) {
            temp.buffers = 0;
            corrupt = true;
            debug(10,"Error loading buffers for %s got string %s. Setting data as invalid\n",
                  temp.key.c_str(),data[2].c_str());
        }
        try {
            temp.timeDone  = std::stol(data[3]);
        }
        catch (...) {
            temp.timeDone = 0;
            corrupt = true;
            debug(10,"Error loading timeDone for %s got string %s. Setting data as invalid\n",
                  temp.key.c_str(),data[3].c_str());
        }
        try {
            temp.totalTime = std::stol(data[4]);
        }
        catch (...) {
            temp.totalTime= 0;
            corrupt = true;
            debug(10,"Error loading totalTime for %s got string %s. Setting data as invalid\n",
                  temp.key.c_str(),data[4].c_str());
        }
        //  Use total time of 0 as the corrupt flag as that would never be the case
        //  for any valid data.
        if (corrupt)
            temp.totalTime = 0;  

	file_lines[data[0]] = temp;
}

std::string FileHandler::curFileKey() {
	return curFile_key;
}

// Gets the key of the given file
std::string FileHandler::getKey(std::string file) {

	// if we have a record for this file then return it's key.
	if(file_lines.count(file) > 0) {
		return file_lines[file].key;
	}

	// if not then return "ERROR"
	debug(30, "WARNING: No file status record for file %s\n", file.c_str());
	return "ERROR";
}
