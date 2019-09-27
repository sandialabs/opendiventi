#ifndef CONTROL_INCLUDED_DIVENTI
#define CONTROL_INCLUDED_DIVENTI
#include <vector>
#include <boost/thread.hpp>
#include <fstream>

#define LINE_SIZE	200	// small.log has lines of size 112, but better safe than sorry
// 
#define QUEUE   0x01
#define REQUEUE 0x02
#define PROCESS 0x04
#define ACTIVE  0x08

class TokuHandler;
class FileHandler;
class InsertThread;
class SyslogHandler;
class SyslogHandlerHandler;

class Control {
public:
	Control(int numThreads);
	~Control();
	void addThread();
	void runThreads();
	void delThreads();
	void setUpThreads(int numThreads);

	TokuHandler *TKhandler;
	std::vector<InsertThread*> inserters;
	int numThreads;
	std::vector<uint64_t> getNumbInserted(){ return {lastNumInserted, oldNumInserted}; }	// Now up to 1 second stale
	std::string getThreadStatus();
	std::string getFileStatus(uint8_t flags);
	std::string ins_to_str(uint64_t);
	void writeFileStatus();
	void readFileStatus();

	// functions for accessing the minimum and maximum rates
	// over given time periods
	float getMinRate(){ return minRate; }
	float getMaxRate(){ return maxRate; }
	float getMinFive(){ return minFive; }
	float getMaxFive(){ return maxFive; }
	float getMinHour(){ return minHour; }
	float getMaxHour(){ return maxHour; }
	float getMinDay(){ return minDay; }
	float getMaxDay(){ return maxDay; }
	
	float getLastRate(){ return lastRate; }
	char** getBadBuf(){ return badBuf; }

	std::fstream *getSampleFile() const {return sampleFile;}

	bool DBStatus = false;
	uint64_t statusEach = (uint64_t) -1;
	uint64_t lastStatus;

private:

	std::fstream *sampleFile;

	FileHandler *fileHandler;
	SyslogHandler **slhs;
	SyslogHandlerHandler *slhh;

	boost::thread *sampler;
	boost::thread *creator;
	void sample();
	float minRate, maxRate, lastRate, minFive, maxFive, minHour, maxHour, minDay, maxDay;
	uint64_t lastNumInserted = 0;
	uint64_t oldNumInserted = 0;// This will be used for the number of inserts past runs of the database

	char* badBuf[LINE_SIZE];	// Want to avoid allocing, which std::string does
	int badBufSize, badBufHead;	// No tail - will just overwrite

	std::set<const char *> *formats;
};

std::set<const char *> *setUpFormat();

#endif
