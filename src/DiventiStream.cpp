#include "diventi.h"
#include "DiventiStream.h"

#include <boost/iostreams/filter/gzip.hpp>
#include <boost/filesystem.hpp>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

// declare reader global which defines what istream function getData will use
read_func readIt;

DiventiStream::DiventiStream(){
	activeFile = new std::ifstream;
	filter = new boost::iostreams::filtering_stream<boost::iostreams::input>;

	lastPos = 0;
	isGZ = false;
	activestream = nullptr;
}

DiventiStream::DiventiStream(std::string fileName){
	activeFile = new std::ifstream;
	filter = new boost::iostreams::filtering_stream<boost::iostreams::input>;

	lastPos = 0;
	isGZ = false;
	activestream = nullptr;
	tryOpen(fileName);
}

DiventiStream::~DiventiStream(){
	close();
	delete filter;
	delete activeFile;
}

/*
 * Returns whether the stream can be read from.
 */
bool DiventiStream::good(){
	return activestream != nullptr && activestream->good();
}

std::string DiventiStream::getFileName(){
	return name;
}

/*
 * Returns the last position read from the most recently open file.
 * This is valid even if good() returns false.
 */
long int DiventiStream::tellPos(){
	return lastPos;
}

/*
 *
 */
void DiventiStream::seekPos(long pos){
	if (isGZ){	// Can't seek in gzipped files. This is a reasonable but not perfect solution.
		std::string discard;
		while (activeFile->tellg() < pos){
			if (!activestream->good()){
				// debug(10, "Error: file bad before requested seek\n");
				break;
			}
			// debug(60, "Scanning gzipped file %li/%li\n", (long)activeFile->tellg(), pos);
			std::getline(*activestream, discard);
			// debug(60, "Discarding line '%s'\n", discard.c_str());
		}
	} else{
		activeFile->seekg(pos);
	}
	lastPos = activeFile->tellg();
}

/*
 * Closes the currently open file.
 */
void DiventiStream::close(){
	if (activestream != nullptr){
		activeFile->clear();
		activeFile->close();
		filter->reset();
		activestream = nullptr;
	}
}

/*
 * Reads and returns a line from the open file.
 * If there is no open file, returns nullptr.
 * Used by diventiProcessed to create a key for the file
 */
std::string* DiventiStream::getLine(){
	std::string* ret = nullptr;

	if (activestream != nullptr){
		ret = new std::string;
		std::getline(*activestream, *ret);

		if (!activestream->good()){
			activeFile->clear();
			lastPos = activeFile->tellg();
			close();
			// debug(30, "File ended (state %d)\n", good());
		} else{
			lastPos = activeFile->tellg();
		}
	}

	return ret;
}


/*
 * Reads and returns a line from the open file.
 *  copies the line to buf provided by caller.
 * If there is no open file, returns 0.
 */
int DiventiStream::getLine(char * buf){
	int ret=0;
	if (activestream != nullptr){
		activestream->getline(buf, MAX_LINE);

		if (!activestream->good()){
			activeFile->clear();
			lastPos = activeFile->tellg();
			close();
			// debug(30, "File ended (state %d)\n", good());
		} else{
			lastPos = activeFile->tellg();
		}
	}

	// get amount of data loaded.
	ret = strlen(buf);
	return ret;
}

int DiventiStream::getBytes(char *buf, int size) {
	int ret = 0;

	if(activestream != nullptr) {
		activestream->read(buf, size);
		ret = activestream->tellg() - lastPos;
		if( !activestream->good()) {
			activeFile->clear();
			lastPos = activeFile->tellg();
			close();
			// debug(30, "File ended (state %d)\n", good());
		} else {
			ret = activestream->tellg() - lastPos;
			lastPos = activeFile->tellg();
		}
	}
	return ret;
}

//general use function for reading data from the stream
//the function pointer argument defines the read function
//size either defines the number of bytes to read or the max line size
int DiventiStream::getData(char *buf, int size) {
	int ret = lastPos;

	if (activestream != nullptr){
		(activestream->*(this->readIt))(buf, size);
		// debug(40, "lastPos: %lu, current: %lu\n", lastPos, (long int)activeFile->tellg());
		if (!activestream->good()){
			activeFile->clear();
			lastPos = activeFile->tellg();
			close();
			// debug(30, "File ended (state %d)\n", good());
		} else{
			lastPos = activeFile->tellg();
			// get amount of data loaded.
		}

	}

	//calculate the number of bytes(characters) read
	ret = lastPos - ret;
	if( ret < 0 ) {
		ret = 0;
	}
	// debug(70, "Position: %ld\n", lastPos);
	return ret;
}

/*
 * Attempts to open a .gz or regular text file.
 * Returns true if successful, false if unsuccessful.
 */
bool DiventiStream::tryOpen(std::string fileName){
	bool ret = false;
	close();
	
	if (boost::filesystem::path(fileName).extension() == ".gz"){
		// debug(40, "Gzipped file '%s'\n", fileName.c_str());
		activeFile->open(fileName, std::ios_base::in | std::ios_base::binary);
		//15, 16000
		filter->push(boost::iostreams::gzip_decompressor());
		filter->push(*activeFile);

		// Point activestream at the filtered file
		activestream = filter;
		isGZ = true;
	} else{
		// debug(40, "Regular file '%s'\n", fileName.c_str());
		activeFile->open(fileName);
		// Point activestream directly at the file
		activestream = activeFile;
		isGZ = false;
	}

	

	// Check if the file was actually opened sucessfully
	if (!activeFile->is_open()){
		activestream = nullptr;
		isGZ = false;
		// debug(20, "Failed to open file\n");
	} else{
		// debug(40, "File opened successfully\n");
		lastPos = 0;
		ret = true;
		name = fileName;
	}
	

	return ret;
}
