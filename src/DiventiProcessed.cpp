#include "diventi.h"
#include "DiventiProcessed.h"
#include "DiventiStream.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <boost/filesystem.hpp>

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

#include <boost/serialization/unordered_map.hpp>
#include <boost/serialization/serialization.hpp>

DiventiProcessed::DiventiProcessed(){
	// If the file containing the serialized list of processed files exists
	boost::filesystem::path processedFile(OPTIONS.dataBaseDir);
	processedFile /= ".Processed";
	debug(50, "Initializing DiventiProcessed at '%s'\n", processedFile.string().c_str());
	if (boost::filesystem::exists(processedFile)){
		try{
			// Load the contents of the file into a local processed table
			debug(40, "Setting up processed set\n");
			std::ifstream ifs(processedFile.native());
			boost::archive::text_iarchive ia(ifs);
			ia >> processed;
			ifs.close();
			debug(40, "Set up processed set\n");
		} catch(boost::archive::archive_exception e){
			debug(40, "Error: %s", e.what());
		}
	} else{
		debug(40, "'%s' does not yet exist\n", processedFile.string().c_str());
		// std::ofstream ofs(processedFile.native());	// Create the file
		// ofs.close();
	}
}

DiventiProcessed::~DiventiProcessed(){
	// Save the table of processed files to a file (overwrites)
	boost::filesystem::path processedFile(OPTIONS.dataBaseDir);
	processedFile /= ".Processed";

	try{
		debug(40, "Saving processed set\n");
		std::ofstream ofs(processedFile.native());
		boost::archive::text_oarchive oa(ofs);
		oa << processed;
		ofs.close();
		debug(40, "Saved processed set\n");
	} catch(boost::archive::archive_exception e){
		debug(40, "Error: %s\n", e.what());
	}
}

/*
 * Returns the number of unread characters in the stream, based on the data
 * in the processed table.
 *
 * If an error occurs, a negative count will be returned.
 */
long DiventiProcessed::charsLeft(std::string fileName, std::string key){
	return getMaxPos(fileName) - getLastPos(key);
}

/*
 * Gets the last stream position of the file when last seen.
 * Returns 0 if the file has not yet been seen.
 */
unsigned long int DiventiProcessed::getLastPos(std::string key){
	long ret = 0;

	if (key.length() > 0){
		debug(90, "Checking last seen pos of file keyed by line '%s'\n", key.c_str());
		ret = processed[key];
		debug(70, "Last pos is %li for file keyed by line '%s'\n", ret, key.c_str());
	} else{
		debug(50, "Error checking last seen pos: key is empty\n");
	}

	return ret;
}

/*
 * Sets the last stream position of a file.
 * Returns true if successful, false if unsuccessful
 */
bool DiventiProcessed::setLastPos(std::string key, long int pos){
	if (pos < 0){
		// TODO: Removed fileName from this error message. Add that error handling outside this function
		debug(50, "Error setting last pos: pos (%ld) must be positive or 0\n", pos);
		return false;
	}

	if (key.length() > 0){
		debug(50, "Setting the last seen pos to %li of file by key '%s'\n", pos, key.c_str());
		processed[key] = pos;
		return true;
	} else{
		debug(50, "Error setting last seen pos: key is empty\n");
		return false;
	}
}

/*
 * Retrieves the key for a file. The key is the first non-empty, non-comment line.
 * If no such lines exist, returns the file name.
 */
// std::string DiventiProcessed::getKey(std::string fileName){
// 	std::string* line;
// 	std::string ret = "";
// 	// Open the file
// 	DiventiStream ds(fileName);
// 	do{
// 		// If there are no more lines to get and no valid line has been found
// 		if (!ds.good()){
// 			ret = fileName; // TODO fix to work with ds.getLine(), which returns a string*
// 			break;
// 		}
// 		debug(99, "Skipping line '%s'\n", ret.c_str());

// 		// Read a line
// 		line = ds.getLine();
// 		if (line != nullptr){
// 			ret = *line;
// 			delete line;
// 		}
// 	} while (ret.length() < 1 || ret.substr(0, 1) == "#");

// 	return ret;
// }

unsigned long int DiventiProcessed::getMaxPos(std::string fileName){
	struct stat buf;
	char* err;
	// int fd = open(fileName.c_str(), O_RDONLY);

	if (stat(fileName.c_str(), &buf) == -1){
		char errStr[256];	// TODO: change to not magic numbers
		err = strerror_r(errno, errStr, 256);
		err = err;
		debug(60, "Failed to find file length: %s\n", errStr);
		return -1;
	}

	// close(fd);
	return buf.st_size;
}

// std::string DiventiProcessed::getProcessed() {
// 	std::string ret = "";
// 	// loop through all elements in processed
// 	for ( auto it = files_processed.begin(); it != files_processed.end(); it++) {
// 		if( it == files_processed.begin()) {
// 			ret += std::string(*it) + ", " + std::to_string(getMaxPos(std::string(*it)));
// 		}
// 		else {
// 			ret += "; " + std::string(*it) + ", " + std::to_string(getMaxPos(std::string(*it)));
// 		}
// 	}
// 	return ret;
// }