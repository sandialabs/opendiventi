/*
 *    Implement a writer that simply writes sequentially 
 *    generated bogus diventi key & values solely to test
 *    how fast we can do inserts on the underlying system.
 *
 */

#include "diventi.h"
#include "TokuHandler.h"
#include "network.h"

#include "IP_Key.h"
#include "Bro_Value.h"


// Needed for cli options
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/chrono.hpp>
#include <boost/thread/thread.hpp>

#include <string>
#include <iostream>
#include <cstdint>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <locale>
#include <sys/time.h>
#include <stdlib.h>

/*
 * Set up some reasonable default values.
 */
const int INSERT_THREADS_DEFAULT = 3;
const int COUNT_DEFAULT = 1000;
const std::string DB_DIR_DEFAULT = "tokudb";
const std::string LOG_FILE_DEFAULT = "test-writes.log";
namespace po = boost::program_options;
template <typename T>
T get(std::string str, po::variables_map vm, boost::property_tree::ptree pt, T deflt);




//   Define some globals that will be used across the threads
uint64_t *inserted;	// Array of counts where each thread writes its count
long total_inserted; //The sum of counts in inserted, calculated each time sample runs
TokuHandler* toku;
std::string logFile;

uint32_t lastRate, maxRate, maxFive, maxHour, maxDay = 0;

uint32_t minRate = (uint32_t) -1, minFive = (uint32_t) -1,
 		minHour = (uint32_t) -1, minDay = (uint32_t) -1;

long getTime(){
	auto now = std::chrono::steady_clock::now();
	return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
}



template<class T>
const char * FormatWithCommas(T value)
{
  std::stringstream ss;
  ss.imbue(std::locale(""));
  ss << std::fixed << value;
  return ss.str().c_str();
}

// number of nanoseconds in
#define FIVEMINUTES 300000000000
#define ONEHOUR     3600000000000
#define ONEDAY      86400000000000

/*
 *  Main function for a thread that periodically samples the current counts
 */
void sample(int iThreads){
	long last = 0;

	// Setup sampler log file
	std::ofstream log;
	log.open(logFile);

	uint64_t lastStatus = 0;
	uint64_t statusEach = 100000000;

	try{
		uint64_t nsTime, fiveMin = getTime(),
		hour = getTime(), day = getTime();
		while(1){	// takes a tally for the current count of insertions
			// About 1 sample/5sec; this is an interrupt point
			boost::this_thread::sleep_for(boost::chrono::seconds(5));	

			long current = 0;
			for (int i = 0; i < iThreads; i++){
				current += inserted[i];
			}
			// Set the count of total inserts
			total_inserted = current;
			nsTime = getTime();
			if(nsTime > (fiveMin + FIVEMINUTES)) {
				debug(60, "resetting five minute min/max\n");
				maxFive = 0;
				minFive = (uint32_t)-1;
				fiveMin += FIVEMINUTES;
			}
			if(nsTime > (hour + ONEHOUR)) {
				debug(60, "resetting one hour min/max\n");
				maxHour = 0;
				minHour = (uint32_t)-1;
				hour += ONEHOUR;
			}
			if(nsTime > (day + ONEDAY)) {
				debug(60, "resetting one day min/max\n");
				maxDay = 0;
				minDay = (uint32_t)-1;
				day += ONEDAY;
			}
			lastRate = (current - last)/5;
			minRate = (lastRate < minRate && lastRate != 0) ? lastRate : minRate;
			maxRate = (lastRate < maxRate) ? maxRate : lastRate;
			minFive = (lastRate < minFive && lastRate != 0) ? lastRate : minFive;
			maxFive = (lastRate < maxFive) ? maxFive : lastRate;
			minHour = (lastRate < minHour && lastRate != 0) ? lastRate : minHour;
			maxHour = (lastRate < maxHour) ? maxHour : lastRate;
			minDay = (lastRate < minDay && lastRate != 0) ? lastRate : minDay;
			maxDay = (lastRate < maxDay) ? maxDay : lastRate;


			debug(1,"Rate: %6ld    total: %12s\n",(current - last)/5, FormatWithCommas(current));
			if (current - last > 0){
				log << current << ":" << getTime() << std::endl;	
				last = current;
				if( current - lastStatus > statusEach) {
					char fileName[40];
					sprintf(fileName, "testWrites_status_%011lu", current);
					std::fstream *statusFile = new std::fstream();
					statusFile->open(fileName, std::fstream::out);
					toku->DBStat(statusFile);
					statusFile->close();
					delete statusFile;
					lastStatus += statusEach;
				}
			}
		}
	} catch(boost::thread_interrupted){
		log.close();
	}
}

/*
 *  CLI processinng
 */
void handle_cli(double start, int iThreads, boost::thread **inserters) {
	/*
	 *   Process CLI commands
	 */
	int done=0;
	std::string q = "";
	std::cout << "Enter 'help' for commands  or 'shutdown' to shutdown.\n";
	try {
		while (done==0) {
			std::cout << "# ";
			std::cin >> q;
			if (q=="help" || q=="h") {
				std::cout << "The following commands are supported:\n";
				std::cout << "   help or h -- print this message\n";
				std::cout << "   shutdown or s -- close down all threads and shutdown\n";
				std::cout << "   status -- print current status\n";
				continue;
			}
			// shutdown
			if (q=="shutdown") {				
				printf("Shutting down diventi  (%d threads)\n", iThreads);
				// Run through each thread and tell them to shutdown
				for (int i=0; i < iThreads; i++) 
					if(inserters[i] != nullptr) {
						inserters[i]->interrupt();
					}
				done=1;
				break;
			}

			if (q=="statistics" || q=="rates") {
				printf("Last Rate: %s\n", FormatWithCommas(lastRate));
				// Small lie- minimum nonzero rate (don't want to report times when we don't have anything to insert...)
				printf("----- Last 5 minutes -----\n");
				printf("Max Rate %s\n", FormatWithCommas(maxFive));
				printf("Min Rate %s\n", FormatWithCommas(minFive));
				printf("------- Last Hour --------\n");
				printf("Max Rate %s\n", FormatWithCommas(maxHour));
				printf("Min Rate %s\n", FormatWithCommas(minHour));
				printf("-------- Last Day --------\n");
				printf("Max Rate %s\n", FormatWithCommas(maxDay));
				printf("Min Rate %s\n", FormatWithCommas(minDay));
				printf("------ Since Start -------\n");
				printf("Max Rate %s\n", FormatWithCommas(maxRate));
				printf("Min Rate %s\n", FormatWithCommas(minRate));
			}

			//  print system status status
			if (q=="status" || q=="s") {
				// print current count
				long total=0;
				for (int i=0; i < iThreads; i++) 				
					total += inserted[i];
				double seconds = getTime() - start;
				seconds = seconds / 1000000000.0;
				printf("Diventi: %ld inserts over %8.0f seconds (rate: %8.0f)\n",
					   total, seconds, total/seconds);
				printf("Last Rate: %s\n", FormatWithCommas(lastRate));

				// most recent rates & overall rates
				// threads running & check status
			}	   	
		}
	}  catch (boost::thread_interrupted) {
	}

} // end of cli




/*
 *     Insert action to be done by each thread as it creates inserts
 *     test values into each 
 *
 *     tnumb is this threads number
 *     count is the number of inserts that this thread should do.
 *
 */

void insert(long count, int tnumb){
	debug(20,"Thread # %d inserting\n", tnumb);

	// Key *k, *rev;
	std::string uid = "sdfkendswrsefwslfs";	
	// Throwaway value - can be same for all
	Bro_Value val(0,EMPTY_PROTO,1,1,1, EMPTY_CONN,1,1,uid.c_str());

	// We ensure there is a unique key by using a falese
	// timestamp
	uint32_t ts = tnumb<< 25;

	//  Some randomly selected values to fill up the key.
	//  The IP address need to 
	uint16_t oPort = 80;
	uint16_t rPort = 443;


	struct in_addr orig, resp;
	srand(time(NULL));
	uint32_t oaddr,raddr; // rnd

	try {
		while (total_inserted < count) {
		
			// Add random to addresses.
			oaddr = 0x7f000000 + rand() % 0xffffff;
			raddr = 0xf0000000 + rand() % 0xffffff;
			//debug(199,"generating random addresses 0x%08x and 0x%08x\n",oaddr, raddr);		

			IP_Key k((in_addr *) &oaddr, ts, oPort, &resp,rPort,false);
			IP_Key r((in_addr *) &raddr, ts, rPort, &orig,oPort,true);
		
			toku->put(k, val);
			toku->put(r, val);
			ts++;
			inserted[tnumb]+=2;
			if (boost::this_thread::interruption_requested()){
				debug(34,"Thread %d got interrupt. Wrapping up\n",tnumb);
				break;
			}
		}
		
	} catch (boost::thread_interrupted) {
		debug(20, "thread %i stopping\n", tnumb);
	}
}


/*
Function to set up the threads

Why do we do this? = A large number of insertion threads when the tree
	is not yet fully formed results in very low performance. (ie 20-50
	thousand per second) while providing much better performance later
	on. This slow-start enables us to have a much faster db in the
	long run.
*/
void setUpThreads(int numThreads, long count, boost::thread **inserters) {
	debug(30, "Running thread slow-start until %u threads\n", numThreads);
	long wait = OPTIONS.threadBase;
	bool not_cleaning = true;
	for(int i = 0; i < numThreads && total_inserted < count; ++i) {
		inserters[i] = new boost::thread(boost::bind(&insert, count, i));
		debug(1,"Made thread number:%i\n",i);
		// For the first 20 threads we delay between adding them
		while(i < 20 && total_inserted < wait && total_inserted < count) {
			if(total_inserted >= (long) OPTIONS.cleanDelay && not_cleaning) {
				toku->enableCleaner();
				not_cleaning = false;
			}
			boost::this_thread::sleep_for(boost::chrono::seconds(1));
		}
		// Is exponential growth on thread by thread basis the best way?
		wait *= OPTIONS.threadExp;
	}
	while(total_inserted < (long) OPTIONS.cleanDelay)
		boost::this_thread::sleep_for(boost::chrono::seconds(1));
	if(not_cleaning)
		toku->enableCleaner();
}

/*----------------------------------------------------------------
   Program flow:
     Start thread creator,
     Each insertion thread does the following:
     for a specified number of entries:
        generate a unique entry
	insert it and its reversed form into the database
	increment a thread-local counter once
	
   An additional thread should be concurrently sampling these counters
   at a rate of about once per 5 seconds
*/

int main(int argc, char const *argv[]){
	argc=argc; argv=argv;
	po::options_description desc("Allowed options");
	desc.add_options()
	    ("help,h", "Produce help message")
	    ("dbDir", po::value<std::string>(), "Directory that stores the Database")
	    ("logFile,l", po::value<std::string>(), "output rates to a log file")
	    ("numIThreads,t", po::value<int>(), "Number of Insertion Threads")
	    ("count,c", po::value<long>(), "Count of key/values to insert (default 1000)")	  
	    #ifdef DEBUG
	    ("debugLvl,d", po::value<int>(), "Set debug level")
	    #endif
	;

	po::variables_map vm;
	po::store(po::command_line_parser(argc, argv).options(desc).run(), vm);
	po::notify(vm);

	boost::property_tree::ptree pt;
	try{
		boost::property_tree::ini_parser::read_ini("config.ini", pt);
	} catch(boost::property_tree::ini_parser::ini_parser_error e){
		std::cout << "Error: config.ini does not exist or incorrectly formatted.\n";
		return 1;
	}

	if (vm.count("help")){
		std::cout << desc << std::endl;
		std::cout << "Alternatively, arguments may be specified the 'config.ini' file.\n\n";
		std::cout << "While running enter 'quit' or 'Quit' to shutdown server.\n";
		return 1;
	}



	long insert_count = get<long>("count", vm, pt, COUNT_DEFAULT);
	int iThreads = get<int>("numIThreads", vm, pt, INSERT_THREADS_DEFAULT);
	std::string dbDir = get<std::string>("dbDir", vm, pt, DB_DIR_DEFAULT);
	logFile = get<std::string>("logFile", vm, pt, LOG_FILE_DEFAULT);


	#ifdef DEBUG
	debug_level = get<int>("debugLvl", vm, pt, 0);
	debug(10,"Setting debug level to %d\n",debug_level);
	#endif

	OPTIONS.dataBaseDir = dbDir.c_str();
	OPTIONS.tokuCleanerPeriod = get<uint32_t>("tokuCleanerPeriod", vm, pt, OPTIONS.tokuCleanerPeriod);
	OPTIONS.tokuCleanerIterations = get<uint32_t>("tokuCleanerIterations", vm, pt, OPTIONS.tokuCleanerIterations);
	OPTIONS.tokuPagesize = get<uint32_t>("tokuPagesize", vm, pt, OPTIONS.tokuPagesize);
	OPTIONS.tokuFanout = get<uint32_t>("tokuFanout", vm, pt, OPTIONS.tokuFanout);
	std::string compress = get<std::string>("tokuCompression", vm, pt, "default");
	if (compress == "no") {
		OPTIONS.tokuCompression = TOKU_NO_COMPRESSION;
	}
	else if (compress == "fast") {
		OPTIONS.tokuCompression = TOKU_FAST_COMPRESSION_METHOD;
	}
	else if (compress == "small") {
		OPTIONS.tokuCompression = TOKU_SMALL_COMPRESSION_METHOD;
	}
	else {
		debug(10, "compression argument %s, using default\n", compress.c_str());
		OPTIONS.tokuCompression = TOKU_DEFAULT_COMPRESSION_METHOD;
	}
	
	// thread delaying
	OPTIONS.threadBase = pt.get<uint64_t>("threadBase", OPTIONS.threadBase);
	OPTIONS.threadExp = pt.get<float>("threadExp", OPTIONS.threadExp);

	// cleaner delaying
	OPTIONS.cleanDelay = pt.get<uint64_t>("cleanDelay", OPTIONS.cleanDelay);

	debug(10,"Starting write tests\n");
	printf("Starting inserts of %ld key/value pairs\n",insert_count);
	
	// Set up local variables for threads
	toku = new TokuHandler();

	boost::thread *sampler;
	boost::thread *cli;
	boost::thread *creator;
	boost::thread **inserters;

	inserters = new boost::thread*[iThreads];
	for (int i=0; i < iThreads; i++) 
		inserters[i] = nullptr;
	inserted = new uint64_t[iThreads];
	for (int i=0; i < iThreads; i++)
		inserted[i]=0;

	// mark start time
	long start = getTime();
	
	creator = new boost::thread(boost::bind(&setUpThreads, iThreads, insert_count, inserters));

	// create cli thread that sends progress updates.
	cli = new  boost::thread(boost::bind(&handle_cli, start, iThreads, inserters));

	// create sampler thread that sends progress updates.
	// doing control of count through here will be less accurate but will allow all threads to continue
	// inserting in order to increase performance to the end
	sampler = new  boost::thread(boost::bind(&sample, iThreads));

	
	/*
	 *   Loop on condition variables waiting for 
	 *   cli shutdown or all inserters threads to finish
	 */ 
	//nop

	/* 
	 * Wait for insertions to complete.  
	 *  We use join to  wait here until every inserter is finished
	 */

	//wait for threads to be made
	boost::this_thread::sleep_for(boost::chrono::seconds(1));

	for (int i=0; i < iThreads; i++) {
		if(inserters[i] != nullptr) {
			inserters[i]->join();
			debug(29,"finished thread %d\n",i);
		}
	}

	//detach the creator
	creator->detach();
	delete creator;

	// mark end time
	long stop = getTime();

	// Clean up the sampler.
	sampler->interrupt();
	sampler->join();
	delete sampler;

	// Clean up the cli. (calling detach since we can't interrupt.
	cli->detach();
	delete cli;
       
	// print out final numbers 0-- w/ time detal
	long total=0;
	for (int i=0;i<iThreads; i++)
		total += inserted[i];

	double seconds = (double) (stop - start);
	seconds = seconds / 1000000000.0;

	double rate = total / seconds;
						   
	printf("Inserts complete %ld inserts over %8.2g seconds  rate: %8.0f\n",
		   total, seconds,rate);

	printf("Last Rate: %s\n", FormatWithCommas(lastRate));
	// Small lie- minimum nonzero rate (don't want to report times when we don't have anything to insert...)
	printf("----- Last 5 minutes -----\n");
	printf("Max Rate %s\n", FormatWithCommas(maxFive));
	printf("Min Rate %s\n", FormatWithCommas(minFive));
	printf("------- Last Hour --------\n");
	printf("Max Rate %s\n", FormatWithCommas(maxHour));
	printf("Min Rate %s\n", FormatWithCommas(minHour));
	printf("-------- Last Day --------\n");
	printf("Max Rate %s\n", FormatWithCommas(maxDay));
	printf("Min Rate %s\n", FormatWithCommas(minDay));
	printf("------ Since Start -------\n");
	printf("Max Rate %s\n", FormatWithCommas(maxRate));
	printf("Min Rate %s\n", FormatWithCommas(minRate));

	delete toku;
}

template <typename T>
T get(std::string str, po::variables_map vm, boost::property_tree::ptree pt, T deflt){
	T ret;
	if (vm.count(str)){
		ret = vm[str].as<T>();
	} else{
		ret = pt.get<T>(str, deflt);
	}
	return ret;
}

