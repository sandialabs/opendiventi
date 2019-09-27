/*
 Note: this is NOT thread safe - that is for FileHandler to deal with
 */

#ifndef _DSTR_INCLUDE_GUARD
#define _DSTR_INCLUDE_GUARD

#include <fstream>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/copy.hpp> //should try to move these to the cpp file

typedef std::istream& (std::istream::*read_func)(char *, std::streamsize);

class DiventiStream{
public:
	DiventiStream();
	DiventiStream(std::string fName);
	~DiventiStream();

	bool tryOpen(std::string fName);
	void close();
	void seekPos(long pos);
	long tellPos();
	std::string* getLine();
	int getLine(char* buf);
	int getBytes(char *buf, int size);
	int getData(char *buf, int size);
	std::string getFileName();
	bool good();
	read_func readIt;
private:
	bool isGZ;
	std::string name;
	std::istream* activestream;
	std::ifstream* activeFile;
	boost::iostreams::filtering_stream<boost::iostreams::input>* filter;

	long int lastPos;
};

#endif
