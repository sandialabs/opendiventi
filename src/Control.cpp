/*
 *   Controls IO threads for reading, parsing, insertion and benchmarking.
 *
 */

#include "Control.h"
#include "diventi.h"
#include "InsertThread.h"
#include "TokuHandler.h"
#include "FileHandler.h"
#include "SyslogHandler.h"

#include <cstddef>
#include <vector>
#include <boost/chrono.hpp>
#include <boost/algorithm/string.hpp>
#include <cmath>

#include <iostream>
// Timing is Linux specific
#include <sys/time.h>


//--------------------- ewest - 07/26/18 ... modified 03/18/19
// function that sets up the set of all sources and writes it to file
// It also sets up the keyCompare function based upon the type of key
// supports multisourcing if the formats all have the same keyCompare function
std::set<const char *> *setUpFormat() {
	std::set<const char *> *formats = new std::set<const char *>();
	//These determine how to get the data, parse it, insert it, and more
	
	debug(25, "Setting up format\n");
	bool IPv4_Key = false;
	bool BASIC_Key = false;
	for( int i = 0; i < 256; i++ ) {
		if (OPTIONS.sources[i] != nullptr) {
			char *format = strndup(OPTIONS.sources[i]->logFormat.c_str(), OPTIONS.sources[i]->logFormat.size());

			formats->insert(format);
			std::string _format = std::string(format);
			//NEWFORMAT Add format identifier to the key type it uses
			if (_format == "bro" || _format == "NetV5" || _format == "netAscii" || _format == "NetV9" || _format == "mon") {
				IPv4_Key = true;
				keyCompare = IPv4_KeyCompare;
			}
			else if (_format == "basic") {
				BASIC_Key = true;
				keyCompare = BASIC_KeyCompare;
			}
			//NEWFORMAT Add ifs for new key types here
			else {
				debug(0, "WARNING: Unrecognized logFormat for source %d, defaulting to bro\n", i);
				OPTIONS.sources[i]->logFormat = "bro";
				IPv4_Key = true;
				keyCompare = IPv4_KeyCompare;
			}
			if( IPv4_Key && BASIC_Key ) {
				debug(0, "source number %d - ", i);
				perror("WARNING: incompatible source logFormats, keys are different lengths\n");
				exit(1);
			}
		}
	}

	if( OPTIONS.dataBaseDir != nullptr ) {
		char filePath[100];
		strcpy(filePath, (char *)OPTIONS.dataBaseDir);
		strcat(filePath, "/tokudb.format");
		std::ifstream rFormatFile(filePath);
		if(rFormatFile) { //if the file already exists
			if (rFormatFile.is_open()) {
				std::string line;
				debug(30, "reading from tokudb.format\n");
				while( getline(rFormatFile, line) ) {
					std::vector<std::string> tokens;
					boost::split(tokens, line,  boost::is_any_of(std::string(":")), boost::token_compress_on);
					//check that the logFormat of source in file matches the source we set
					//create a source if there isn't one already so that we can still return that data
					short index = std::stoi(tokens[0]);

					debug(40, "processing old source: %d, logFormat: %s and tag: %s\n", index, tokens[1].c_str(), tokens[2].c_str());

					if( OPTIONS.sources[index] == nullptr ) {
						OPTIONS.sources[index] = new source(tokens[1], tokens[2], 0, "", "", "", 0);
					}
					else {
						debug(40, "new source of same number takes precedence, error checking\n");
						if( OPTIONS.sources[index]->logFormat != tokens[1] || OPTIONS.sources[index]->tag != tokens[2]) {
							debug(0, "source number %d - ", index);
							perror("WARNING: unequal logFormat or tag of current source and past source\n");
							exit(1);
						}
					}
					//NEWFORMAT Add format identifier to the key type it uses
					if (tokens[1] == "bro" || tokens[1] == "NetV5" || tokens[1] == "netAscii" || tokens[1] == "NetV9" || tokens[1] == "mon") {
						IPv4_Key = true;
						keyCompare = IPv4_KeyCompare;
					}
					else if (tokens[1] == "basic") {
						BASIC_Key = true;
						keyCompare = BASIC_KeyCompare;
					}
					//NEWFORMAT Add ifs for new key types here
					if( IPv4_Key && BASIC_Key ) {
						debug(0, "source number %d - ", index);
						perror("WARNING: incompatible previous and current logFormats, keys are different lengths\n");
						exit(1);
					}
				}
				rFormatFile.close();
			}
		}
		else {
			std::ofstream wFormatFile(filePath);
			if( wFormatFile.is_open() ) {
				for( int i = 0; i < 256; i++ ) {
					if( OPTIONS.sources[i] != nullptr ) {
						wFormatFile << i << ":" << OPTIONS.sources[i]->logFormat << ":" << OPTIONS.sources[i]->tag << "\n";
					}
				}
				wFormatFile.close();
			}
			else {
				debug(20, "Didn't create %s\n", filePath);
			}
		}
	}
	return formats;
}
//---------------------

long calcNS(timespec& ts){
	return ts.tv_sec * 1000000000 + ts.tv_nsec;
}
long getTime(){
	auto now = std::chrono::steady_clock::now();
	return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
}

Control::Control(int numThreads){
	this->numThreads = numThreads;
	// if (OPTIONS.inputDir == nullptr){
	// 	debug(5, "No input directory specified!\n");
	// 	OPTIONS.inputDir = "";
	// }
	debug(75, "Creating handlers\n");
	TKhandler = new TokuHandler();
	debug(75, "Created TKhandler\n");

	fileHandler = new FileHandler();
	debug(75, "Created fileHandler\n");

	formats = setUpFormat();

	#ifdef BENCHMARK
	sampleFile = new std::fstream();
	#endif

	slhs = (SyslogHandler **)calloc(256, sizeof(SyslogHandler *));
	slhh = nullptr;
	int position = 0;

	bool syslog = false;

	for (int i = 0; i < 256; i++){
		if( OPTIONS.sources[i] != nullptr && OPTIONS.sources[i]->syslogPort != 0 ){
			slhs[position] = new SyslogHandler(OPTIONS.sources[i], i);
			position += 1;
			syslog = true;
		}
	}

	if(syslog) {
		slhh = new SyslogHandlerHandler(slhs, position); //create wrapper class for syslog, we 0 index so +1 
	}

	creator = new boost::thread(boost::bind(&Control::setUpThreads, this, numThreads));

	sampler = nullptr;
	maxRate = 0;
	minRate = INFINITY;
	maxFive = 0;
	minFive = INFINITY;
	maxHour = 0;
	minHour = INFINITY;
	maxDay  = 0;
	minDay  = INFINITY;
	lastNumInserted = 0;
	lastRate = 0;
}

Control::~Control(){
	debug(79,"writing file inserts\n");
	writeFileStatus();
	debug(79,"deleting Threads\n");
	delThreads();
	debug(79,"deleting TKhandler\n");
	delete TKhandler;
	debug(79,"deleting fileHandler\n");
	delete fileHandler;
	debug(50, "deleting syslogHandlers\n");
	for(int i = 0; i < 256; i++) {
		if (slhs[i] != nullptr) {
			delete slhs[i];
		}
	}
	delete slhs;
	debug(50, "deleting syslogHandlerHandler\n");
	if (slhh != nullptr){
		delete slhh;
	}
	debug(50, "deleting formats\n");
	formats->clear();
	delete formats;
	// delete functions;
	#ifdef BENCHMARK
	delete sampleFile;
	#endif
	debug(79,"deleted components\n");
}

// A thread runs on this function until the number of insertion threads desired is reached
void Control::setUpThreads(int numThreads){
	debug(20, "Running thread slow-start until %u threads\n", numThreads);
	uint64_t wait = OPTIONS.threadBase; // wait initial amount to add second thread
	bool not_cleaning = true;
	for(int i = 0; i < numThreads; ++i) {
		inserters.push_back(new InsertThread(TKhandler, fileHandler, slhh, i));
		debug(50,"Made thread number:%i\n",i);
		// For the first 20 threads we delay between adding them
		while(i < 20 && lastNumInserted + oldNumInserted < wait) {
			if(lastNumInserted + oldNumInserted >= OPTIONS.cleanDelay && not_cleaning) {
				TKhandler->enableCleaner();
				not_cleaning = false;
			}
			boost::this_thread::sleep_for(boost::chrono::seconds(1));
		}
		// Is exponential growth on thread by thread basis the best way?
		wait *= OPTIONS.threadExp;
	}
	while(lastNumInserted + oldNumInserted < OPTIONS.cleanDelay)
		boost::this_thread::sleep_for(boost::chrono::seconds(1));
	if(not_cleaning)
		TKhandler->enableCleaner();
}

// uint64_t Control::getNumbInserted(){
// 	std::size_t i;
// 	uint64_t result=0;
// 	for (i =0; i < inserters.size(); i++) {
// 		result += inserters[i]->getNumInserted();
// 	}
// 	return result;
// }

std::string Control::getThreadStatus() {
	std::string ret = "";
	for( auto it = formats->begin(); it != formats->end(); it++ ) {
		 ret += (inserters[0]->getFormat(std::string(*it)))->getStats();
	}
	return ret;
}

std::string Control::ins_to_str(uint64_t inserts) {
	std::string ret = std::to_string(inserts);

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
	Function to print the status of each file that diventi is handling

	ewest - 02/15/19
*/
std::string Control::getFileStatus(uint8_t flags) {
	std::set<std::string> processed;
	std::set<std::string> queued;
	std::set<std::string> reprocess;
	std::set<std::string> processing;
	std::string ret = "";
	for (uint i = 0; i < inserters.size(); i++){
		std::vector<std::set<std::string>> data = inserters[i]->fileStat();
		// grab the currently active file
		std::string active = inserters[i]->getActiveFile();
		if (active != "") {
			processing.insert(active);
		}
		
		debug(60, "Done with grabbing file status\n");
		//grab the files that have been processed
		for (auto it = data[0].begin(); it != data[0].end(); it++) {
			processed.insert(std::string(*it));
		}
		//grab the files that are waiting to be processed
		for (auto it = data[1].begin(); it != data[1].end(); it++) {
			queued.insert(std::string(*it));
		}
		debug(60, "Done creating sets\n");
	}

	//remove any files from processed that are currently in progress
	for (auto it = processing.begin(); it != processing.end(); it++) {
		processed.erase(std::string(*it));
	}

	//remove any files that appear in processed and queued
	//add these files to reprocess
	for (auto it = processed.begin(); it != processed.end(); it++) {
		if (queued.count(std::string(*it)) == 1) {
			processed.erase(std::string(*it));
			queued.erase(std::string(*it));
			reprocess.insert(std::string(*it));
		}
	}
	//flags variable determines what sets are included in the output
	if (flags & QUEUE) {
		ret += "====               Queued               ====\n";
		for (auto it = queued.begin(); it != queued.end(); it++) {
			ret += std::string(*it) + "\n";
		}
	}

	if (flags & REQUEUE) {
		ret += "====  reQueued - Processed but changed  ====\n";
		for (auto it = reprocess.begin(); it != reprocess.end(); it++) {
			uint64_t file_count = 0;
			for (uint i = 0; i < inserters.size(); i++) {
				file_count += inserters[i]->fileCount(std::string(*it));
			}
			ret += std::string(*it) + " -- " + inserters[0]->fileInfo(std::string(*it))+"; inserts: "+ins_to_str(file_count)+")\n";
		}
	}

	if (flags & PROCESS) {
		ret += "==== Processed & Being watched (if set) ====\n";
		//rbegin and rend to traverse the list backward
		for (auto it = processed.rbegin(); it != processed.rend(); it++) {
			uint64_t file_count = 0;
			for (uint i = 0; i < inserters.size(); i++) {
				file_count += inserters[i]->fileCount(std::string(*it));
			}
			ret += std::string(*it) + " -- " + inserters[0]->fileInfo(std::string(*it))+"; inserts: "+ins_to_str(file_count)+")\n";
		}
	}

	if (flags & ACTIVE) {
		ret += "====        Currently pointing at       ====\n";
		for (auto it = processing.begin(); it != processing.end(); it++) {
			uint64_t file_count = 0;
			for (uint i = 0; i < inserters.size(); i++) {
				file_count += inserters[i]->fileCount(std::string(*it));
			}
			ret += std::string(*it) + " -- " + inserters[0]->fileInfo(std::string(*it))+"; inserts: "+ins_to_str(file_count)+")\n";
		}
	}
	return ret;
}

/*
	Function to write the status of each file down in the database environment

	ewest - 02/22/19
*/
void Control::writeFileStatus() {
	std::set<std::string> process;
	//loop through each inserter and ask it for the files it has
	for (uint i = 0; i < inserters.size(); i++){
		std::vector<std::set<std::string>> data = inserters[i]->fileStat();
		for (auto it = data[0].begin(); it != data[0].end(); it++) {
			process.insert(std::string(*it));
		}
	}
	// Write the information we have on each file to the file
	if( OPTIONS.dataBaseDir != nullptr ) {
		char filePath[100];
		strcpy(filePath, (char *)OPTIONS.dataBaseDir);
		strcat(filePath, "/tokudb.inserts");
		std::ofstream insertsFile(filePath);
		if( insertsFile.is_open() ) {
			// Write the total number of insertions
			uint64_t inserted = 0;
			for (uint i = 0; i < inserters.size(); i++){
				inserted += inserters[i]->getNumInserted();
			}
			inserted += oldNumInserted;
			insertsFile << std::to_string(inserted) << "\n";
			// Write the data for each file
			for (auto it = process.begin(); it != process.end(); it++) {
				uint64_t file_count = 0;
				for (uint i = 0; i < inserters.size(); i++) {
					file_count += inserters[i]->fileCount(std::string(*it));
				}
				debug(55, "writing %s info to tokudb.inserts\n", std::string(*it).c_str());
				insertsFile << std::string(*it) << ";" << inserters[0]->statsToFile(std::string(*it))<<";"<<std::to_string(file_count)<<"\n";
			}
		}
		else {
			debug(10, "Couldn't create tokudb.inserts");
		}
		insertsFile.close();
	}
}

void Control::readFileStatus() {
	//if the file doesn't exist then do nothing
	//if the file does exist then read in the data and modify the data that insertion/fileHandler have
	if( OPTIONS.dataBaseDir != nullptr ) {
		char filePath[100];
		strcpy(filePath, (char *)OPTIONS.dataBaseDir);
		strcat(filePath, "/tokudb.inserts");
		std::ifstream insertsFile(filePath);
		if(insertsFile) { //if file exists do stuff otherwise do nothing
			std::string line;

			//first line is the total number of inserts
			getline(insertsFile, line);
			debug(10, "setting total old inserts to: %s\n", line.c_str());
			oldNumInserted = std::stol(line);
			
			// Each following line corresponds to data for one file
			while(getline(insertsFile, line)) {
				std::vector<std::string> tokens;
				boost::split(tokens, line,  boost::is_any_of(std::string(";")), boost::token_compress_on);
				if( tokens.size() == 6 ){
					inserters[0]->statsFromFile(tokens);
				}
				else {
					perror("Control.ccp::readFileStatus -> Insertion count from tokudb.inserts does not have required number of tokens(6) split by ';'\n");
					exit(1);
				}
				//Just for debugging
				// for( uint i = 0; i < tokens.size(); i++ ) {
				// 	debug(0, "token: %s\n", tokens[i].c_str());
				// }
			}
		}
		insertsFile.close();
	}
}

void Control::runThreads(){
	debug(30, "reading in file status/inserts\n");
	readFileStatus();
	debug(10,"numThreads in Control: %ld\n", inserters.size());
	// Spawn a thread to sample insertion amounts for each insertion thread
	// Start up sampler before so that first inserts don't count as happening super fast
	if (sampler == nullptr){
		sampler = new boost::thread(boost::bind(&Control::sample, this));
	}

	for (std::size_t i = 0; i < inserters.size(); ++i)
	{
		debug(10,"run thread number:%li\n", i);
		inserters[i]->thread();
	}
}

void Control::delThreads(){
	if (sampler != nullptr && sampler->joinable()){
		sampler->interrupt();
		sampler->join();
		delete sampler;
		sampler = nullptr;
	}

	if (creator != nullptr && creator->joinable()){
		creator->interrupt();
		creator->join();
		delete creator;
		creator = nullptr;
	}

	for (std::size_t i = 0; i < inserters.size(); ++i)
	{
		delete inserters[i]; //deleting an insertThread uses join to wait for the tread to finish and then deletes the thread
		inserters[i] = nullptr;
		debug(10,"deleted insertion thread number %ld\n",i);
	}
}

// number of nanoseconds in
#define FIVEMINUTES 300000000000
#define ONEHOUR     3600000000000
#define ONEDAY      86400000000000

void Control::sample(){
	#ifdef BENCHMARK
	time_t tt = time(NULL);
	struct tm* t = localtime(&tt);
	char outFile[27];
	strftime(outFile, 27, "/tmp/diventi_%Y%m%d_%H%M", t);
	debug(20, "Writing samples to '%s'\n", outFile);
	sampleFile->open(outFile, std::fstream::out);
	#endif

	lastStatus = 0; // for db status polling, number of inserts which we last polled at
	uint64_t inserted = 0;
	uint64_t nsTime, lastTime = getTime(), fiveMin = getTime(),
	hour = getTime(), day = getTime();
	std::size_t i;
	try{
		while (1){
			// About 1 samples/s; this is an interrupt point
			boost::this_thread::sleep_for(boost::chrono::seconds(1));

			inserted = 0;
			for (i = 0; i < inserters.size(); i++){
				inserted += inserters[i]->getNumInserted();
			}
			nsTime = getTime();
			if(nsTime > (fiveMin + FIVEMINUTES)) {
				debug(60, "resetting five minute min/max\n");
				maxFive = 0;
				minFive = INFINITY;
				fiveMin += FIVEMINUTES;
			}
			if(nsTime > (hour + ONEHOUR)) {
				debug(60, "resetting one hour min/max\n");
				maxHour = 0;
				minHour = INFINITY;
				hour += ONEHOUR;
			}
			if(nsTime > (day + ONEDAY)) {
				debug(60, "resetting one day min/max\n");
				maxDay = 0;
				minDay = INFINITY;
				day += ONEDAY;
			}
			lastRate = ((float)inserted - lastNumInserted) / (nsTime - lastTime);
			minRate = (lastRate < minRate && lastRate != 0) ? lastRate : minRate;
			maxRate = (lastRate < maxRate) ? maxRate : lastRate;
			minFive = (lastRate < minFive && lastRate != 0) ? lastRate : minFive;
			maxFive = (lastRate < maxFive) ? maxFive : lastRate;
			minHour = (lastRate < minHour && lastRate != 0) ? lastRate : minHour;
			maxHour = (lastRate < maxHour) ? maxHour : lastRate;
			minDay = (lastRate < minDay && lastRate != 0) ? lastRate : minDay;
			maxDay = (lastRate < maxDay) ? maxDay : lastRate;
			debug(90, "lastTime, nsTime, inserted, minRate, maxRate: %lu, %lu, %lu, %f, %f\n", lastTime, nsTime, inserted, minRate, maxRate);

			if (inserted - lastNumInserted > 0){
				#ifdef BENCHMARK
				// timestamp the current number of inserted logs from this run and any previous
				(*sampleFile) << inserted + oldNumInserted<< ":" << nsTime << std::endl;
				if( inserted - lastStatus > statusEach && DBStatus) {
					char fileName[40];
					sprintf(fileName, "/tmp/diventi_status_%011lu", inserted);
					std::fstream *statusFile = new std::fstream();
					statusFile->open(fileName, std::fstream::out);
					TKhandler->DBStat(statusFile);
					statusFile->close();
					delete statusFile;
					lastStatus += statusEach;
				}
				#endif
				lastNumInserted = inserted;
				lastTime = nsTime;
			}
		}

	} catch(boost::thread_interrupted){
		#ifdef BENCHMARK
		sampleFile->close();
		#endif
	}
}
