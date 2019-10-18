/*
 * Tracks processed files by last position read.
 * Indexed by first line of the file.
 * NOT thread safe - that is for FileHandler to deal with
 */

#ifndef _DPROCESSED_INCLUDE_GUARD
#define _DPROCESSED_INCLUDE_GUARD

#include <unordered_map>

class DiventiProcessed{
public:
	DiventiProcessed();
	~DiventiProcessed();

	long charsLeft(std::string fileName, std::string key);
	unsigned long int getLastPos(std::string key);
	bool setLastPos(std::string key, long int pos);
	unsigned long int getMaxPos(std::string fileName);
	
private:
	
	std::unordered_map<std::string, unsigned long int> processed;
};

#endif