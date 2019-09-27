/*
 *   Main server code that processes cli and options 
 *   then starts a server ingesting data and answering 
 *   questions.
 *
 *   example cli invocation:
 *      ServersideCli -debugLvl 2 --d /database/ -w
 *
 */

#include "diventi.h"
#include "ServersideCli.h"

#include "TokuHandler.h"
#include "Control.h"
#include "Server.h"

#include "network.h"

#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/chrono.hpp>
#include <boost/thread/thread.hpp>

#include <string>
#include <iostream>
#include <chrono>
#include <signal.h>
#include <cstdlib>


//defaults for most are defined in diventi.h
const int QUERY_THREADS_DEFAULT = 1;

const std::string DB_DIR_DEFAULT = "tokudb";
const std::string FILE_NAME_FORMAT_DEFAULT = "conn.*\\.log(\\.gz)?";
const std::string LOG_FORMAT_DEFAULT = "bro";

const std::string SYSLOG_FIELDS_DEFAULT = "#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents";

//\n#types  time    string  addr    port    addr    port    enum    string  interval        count   count   string  bool    count   string  count   count   count   count   set[string]";


long getTimeLocal(){
	auto now = std::chrono::system_clock::now();
	return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
}

std::string sec_to_time(double seconds) {
	uint secs = (int)seconds;
	uint mins = secs/60;
	uint hrs = mins/60;
	uint days = hrs/24;
	std::string h = std::to_string(hrs%24);
	std::string m = std::to_string(mins%60);
	std::string s = std::to_string(secs%60);
	if (h.size() != 2) {
		h = "0" + h;
	}
	if (m.size() != 2) {
		m = "0" + m;
	}
	if (s.size() != 2) {
		s = "0" + s;
	}
	return std::to_string(days) + " days " + h + ":" + m + ":" + s;
}


/*
 *  CLI processinng
 */
void handle_cli(double start, Control *control) {
	/*
	 *   Process CLI commands
	 */
	int done=0;
	std::string q = "";

	// ------------------------------
	// Code for catching ctl-c 
	// ewest - 06/28/19
	// lambda for handling a ctl-c event
	auto ctlCHandler = [](int s) {
		if( s == SIGINT ) {
			printf("\nCaught SIGINT, use shutdown or exit to stop\n");
		}
		return;
	};
	struct sigaction sigIntHandler;
	sigIntHandler.sa_handler = ctlCHandler;
	sigemptyset(&sigIntHandler.sa_mask);
	sigIntHandler.sa_flags = 0;

	sigaction(SIGINT, &sigIntHandler, NULL);
	// ------------------------------

	// Ensure all of the insert threads can signal 
	//   handler when they're done
	// TODO
	
	std::cout << "Enter 'help' for commands  or 'shutdown' to shutdown.\n";
	try {
		while (done==0) {
			std::cout << "# ";
			std::cin >> q;
			if (q=="help" || q=="h") {
				std::cout << "The following commands are supported:\n";
				std::cout << "   help or h -- print this message\n";
				std::cout << "   shutdown(or exit) -- close down all threads and shutdown\n";
				std::cout << "   status(or s) -- print current status\n";
				std::cout << "   statistics(or rates) -- print out insertion rate statistics\n";
				std::cout << "   filestatus(or fstat) -- print out the list of in progress, and queued files\n";
				std::cout << "   processed(or fproc) -- print out the list of all processed files\n";
				std::cout << "   allfiles(or fall) -- print out the list of all files in progress, processed, and queued\n";
				std::cout << "   date -- print the current date and time\n";
				#ifdef DEBUG
				std::cout << "   debugLvl -- adjust the debug level\n";
				#endif
				#ifdef BENCHMARK
				std::cout << "   db_stats -- enable/disable gathering db stats and set how often\n";
				#endif
				continue;
			}
			// shutdown
			if (q=="shutdown" || q=="exit") {				
				printf("Shutting down diventi  (XX threads)\n");
				// Run through each thread and tell them to shutdown
				done=1;
				break; 
			}
			//  print system status status
			if (q=="status" || q=="s") {
				// print current count


				std::vector<uint64_t> totals;
				totals = control->getNumbInserted();
				// string totalstr = total.to_string();
				// int comma_pos = totalstr.length() - 3;
				// while(comma_pos > 0) {
				// 	totalstr.insert(comma_pos, ",");
				// 	comma_pos -= 3;
				// }
				double seconds = getTimeLocal() - start;
				seconds = seconds / 1000000000.0;
				printf("Diventi server up for %s\n",sec_to_time(seconds).c_str());
				if(totals[1] > 0) {
					printf("Diventi: %s inserts over %8.3f seconds (rate: %s) %s total inserts with %s old\n",
					control->ins_to_str(totals[0]).c_str(), seconds, control->ins_to_str((int)(totals[0]/seconds)).c_str(), 
					control->ins_to_str(totals[0] + totals[1]).c_str(), control->ins_to_str(totals[1]).c_str());
				}
				else {
					printf("Diventi: %s inserts in %8.3f seconds (rate: %s)\n",
					control->ins_to_str(totals[0]).c_str(), seconds, control->ins_to_str((int)(totals[0]/seconds)).c_str());
				}
				

				
				printf("Last Rate: %s\n", control->ins_to_str(control->getLastRate() * 1e9).c_str());
				// q = "statistics";
				
				// TODO -- sampler's most recent results.
				// most recent rates & overall rates
				// threads running & check status
			}
			#ifdef BENCHMARK
			if (q=="dbStats") {
				if (!control->DBStatus) {
					std::cout << "dbStats enabled will be written to /tmp\n";
					std::cout << "run dbStats again to disable\n";
					std::cout << "poll every x inserts. x = ";
					std::cin >> q;
					try {
						control->statusEach = stoi(q);
						// get largest multiple of statusEach less than current inserts. Set that as last time polled
						control->lastStatus = (control->getNumbInserted()[0] / control->statusEach) * control->statusEach;
						control->DBStatus = true;
					} catch(std::invalid_argument) {
						std::cout << "\nbad input, needs to be number. Try again.\n";
					}
				}
				else {
					control->DBStatus = false;
					std::cout << "dbStats will no longer be gathered\n";
				}
				continue;
			}
			#endif
			#ifdef DEBUG
			if (q == "debugLvl") {
				std::cout << "New debugLvl = ";
				std::cin >> q;
				// set debug to q
				try {
					debug_level = stoi(q);
				} catch(std::invalid_argument) {
					std::cout << "\nbad input, needs to be number. Try again.\n";
				}
				continue;
			}
			#endif
			// print insertion statistics
			if (q=="statistics" || q=="rates") {
				printf("Last Rate: %s\n", control->ins_to_str(control->getLastRate() * 1e9).c_str());
				// Small lie- minimum nonzero rate (don't want to report times when we don't have anything to insert...)
				printf("----- Last 5 minutes -----\n");
				printf("Max Rate %s\n", control->ins_to_str(control->getMaxFive() * 1e9).c_str());
				printf("Min Rate %s\n", control->ins_to_str(control->getMinFive() * 1e9).c_str());
				printf("------- Last Hour --------\n");
				printf("Max Rate %s\n", control->ins_to_str(control->getMaxHour() * 1e9).c_str());
				printf("Min Rate %s\n", control->ins_to_str(control->getMinHour() * 1e9).c_str());
				printf("-------- Last Day --------\n");
				printf("Max Rate %s\n", control->ins_to_str(control->getMaxDay() * 1e9).c_str());
				printf("Min Rate %s\n", control->ins_to_str(control->getMinDay() * 1e9).c_str());
				printf("------ Since Start -------\n");
				printf("Max Rate %s\n", control->ins_to_str(control->getMaxRate() * 1e9).c_str());
				printf("Min Rate %s\n", control->ins_to_str(control->getMinRate() * 1e9).c_str());
			} 
			// print descriptions of the files that are being ingested
			if (q=="filestatus" || q=="fstat") {
				printf("----- ACTIVE FILES ----\n");
				printf("%s", control->getFileStatus(QUEUE | REQUEUE | ACTIVE).c_str());
				printf("------------------------\n");
			}
			if (q=="processed" || q=="fproc") {
				printf("------ OLD FILES ------\n");
				printf("%s", control->getFileStatus(REQUEUE | PROCESS).c_str());
				printf("------------------------\n");
			}
			if (q=="allfiles" || q=="fall") {
				printf("------ ALL FILES ------\n");
				printf("%s", control->getFileStatus(QUEUE | REQUEUE | PROCESS | ACTIVE).c_str());
				printf("------------------------\n");
			}
			if(q=="date") {
				long cur_time = getTimeLocal();
				char *buf = new char();
				time_t time = (time_t)(cur_time/1000000000);
				struct tm *timestruct;
				timestruct = localtime(&time);
				strftime(buf, 20, "%T %D", timestruct);
				
				printf("Current time: %s\n", buf);
				delete buf;
			}
			// if(q=="threads") {
			// 	std::cout << "new number of threads = ";
			// 	std::cin >> q;
			// 	try {
			// 		control->adjustThreads(stoul(q));
			// 	} catch(std::invalid_argument) {
			// 		std::cout << "\nbad input, needs to be number. Try again.\n";
			// 	}
			// }
		}
	}  catch (boost::thread_interrupted) {
	}

} // end of cli



namespace po = boost::program_options;

template <typename T>
T get(std::string str, po::variables_map vm, boost::property_tree::ptree pt, T deflt);

int main(int argc, char const *argv[]){

	argc=argc; argv=argv;
	po::options_description desc("Allowed options");

	// removed command line arguments for specifying source to move to config
	// ewest - 03/18/19
	desc.add_options()
	    ("help,h", "Produce help message")
	    ("dbDir,d", po::value<std::string>(), "Directory that stores the Database")
	    ("numIThreads,t", po::value<int>(), "Number of Insertion Threads")
	    ("numQThreads,q", po::value<int>(), "Number of Query Threads")
	    ("watchIDir,w", "Continue to monitor Insert Dir")
	    ("queryPort,p", po::value<short>(), "Set the port to listen on for incoming queries.")
	    // The following are arguments specific to tokuDB
	    ("tokuPagesize,b", po::value<uint32_t>(), "Size of each buffer in the tree")
	    ("tokuFanout,f", po::value<uint32_t>(), "Number of children each internal node has")
	    ("tokuCompression,s", po::value<std::string>(), "Level of compression(no, fast, default, small)")
	    ("tokuCleanerPeriod,c", po::value<uint32_t>(), "How long to wait between runs of the cleaner")
	    ("tokuCleanerIterations,i", po::value<uint32_t>(), "Number of nodes cleaned on each run of cleaner")
	    // ("bufSize", po::value<unsigned long>(), "UDP buffer size")
	    #ifdef DEBUG
	    ("debugLvl", po::value<int>(), "Set debug level")
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

	// OPTIONS.syslog = pt.get<bool>("syslog", vm.count("syslog"));

	std::string inDir;

	// check that we will be getting a valid source from somewhere
	// only check source1 because give us them in order or else

	// if (!vm.count("inputDir") && !vm.count("syslog") && pt.count("source1") == 0){
	// 	try{
	// 		inDir = pt.get<std::string>("inputDir");
	// 	} catch(boost::property_tree::ptree_error e){
	// 		std::cout << "Invalid arguments. Use --help or -h for usage information.\n";
	// 		return 1;
	// 	}
	// } else if(vm.count("inputDir")){
	// 	inDir = vm["inputDir"].as<std::string>();
	// }

	// OPTIONS.syslog = pt.get<bool>("syslog", vm.count("syslog"));

	int qThreads = get<int>("numQThreads", vm, pt, QUERY_THREADS_DEFAULT);
	std::string dbDir = get<std::string>("dbDir", vm, pt, DB_DIR_DEFAULT);
	// std::string fNameFormat = get<std::string>("fileNameFormat", vm, pt, FILE_NAME_FORMAT_DEFAULT);
	// std::string logFormat = get<std::string>("logFormat", vm, pt, LOG_FORMAT_DEFAULT);
	// std::string syslogArgs = get<std::string>("syslogArgs", vm, pt, SYSLOG_FIELDS_DEFAULT);

	#ifdef DEBUG
	debug_level = get<int>("debugLvl", vm, pt, 0);
	#endif

	OPTIONS.dataBaseDir = dbDir.c_str();
	// OPTIONS.inputDir = inDir.c_str();
	// OPTIONS.fNameFormat = fNameFormat.c_str();
	OPTIONS.insertThreads = get<int>("numIThreads", vm, pt, OPTIONS.insertThreads);
	OPTIONS.continuous = pt.get<bool>("watchIDir", vm.count("watchIDir"));
	// OPTIONS.logFormat = logFormat.c_str();
	OPTIONS.syslogPort = get<short>("syslogPort", vm, pt, OPTIONS.syslogPort);
	OPTIONS.queryPort = get<short>("queryPort", vm, pt, OPTIONS.queryPort);
	OPTIONS.syslogBufsize = get<unsigned long>("syslogBufsize", vm, pt, OPTIONS.syslogBufsize);
	OPTIONS.syslogOffset = get<short>("syslogOffset", vm, pt, OPTIONS.syslogOffset);
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
		OPTIONS.tokuCompression = TOKU_DEFAULT_COMPRESSION_METHOD;
	}
	// OPTIONS.syslogArgs = syslogArgs.c_str();

	// thread delaying
	OPTIONS.threadBase = pt.get<uint64_t>("threadBase", OPTIONS.threadBase);
	OPTIONS.threadExp = pt.get<float>("threadExp", OPTIONS.threadExp);

	// cleaner delaying
	OPTIONS.cleanDelay = pt.get<uint64_t>("cleanDelay", OPTIONS.cleanDelay);
	// Read in descriptions of sources 1->256
	bool foundSource = false;
	for( uint i = 1; i < 257; i++ ) {
		std::string src = "source" + std::to_string(i);
		OPTIONS.sources[i] = nullptr;
		if (pt.count(src) > 0) {
			foundSource = true;
			debug(20, "creating source %d\n", i);
			OPTIONS.sources[i] = new source(
				pt.get<std::string>(src+".logFormat", LOG_FORMAT_DEFAULT),
				pt.get<std::string>(src+".tag", src),
				pt.get<short>(src+".syslogPort", 0),
				pt.get<std::string>(src+".syslogArgs", ""),
				pt.get<std::string>(src+".inputDir", ""),
				pt.get<std::string>(src+".fileNameFormat", "FILE_NAME_FORMAT_DEFAULT"),
				pt.get<short>(src+".kafkaPort", 0)
			);
			
			// ensure that one and only one input(file, syslog, kafka) is used for each source
			if (OPTIONS.sources[i]->syslogPort == 0) {
				if (std::string(OPTIONS.sources[i]->inputDir) == "") {
					if( OPTIONS.sources[i]->kafkaPort == 0) {
						std::cout << "CONFIG WARNING: No input for source"+std::to_string(i)+"\n";
					}
				}
			}
			// print out the information on this source
			debug(30, "logFormat:      %s\n", OPTIONS.sources[i]->logFormat.c_str());
			debug(30, "tag:            %s\n", OPTIONS.sources[i]->tag.c_str());
			debug(30, "syslogPort:     %s\n", (OPTIONS.sources[i]->syslogPort == 0)? "not used":std::to_string(OPTIONS.sources[i]->syslogPort).c_str());
			debug(30, "syslogArgs:     %s\n", (OPTIONS.sources[i]->syslogArgs == "")? "not used":OPTIONS.sources[i]->syslogArgs.c_str());
			debug(30, "inputDir:       %s\n", (OPTIONS.sources[i]->inputDir == "")? "not used":OPTIONS.sources[i]->inputDir.c_str());
			debug(30, "fileNameFormat: %s\n", (OPTIONS.sources[i]->inputDir == "")? "not used":OPTIONS.sources[i]->fNameFormat.c_str());
			debug(30, "kafkaPort:      %s\n", (OPTIONS.sources[i]->kafkaPort == 0)? "not used":std::to_string(OPTIONS.sources[i]->kafkaPort).c_str());
		}
	}

	if(!foundSource) {
		std::cout << "WARNING: No data source given in config.ini, server will not insert\n";
	}

	Control* control = new Control(OPTIONS.insertThreads);
	//->TKhandler (below)
	Server* server = new Server(OPTIONS.queryPort, control, qThreads);

	// mark time
	long start = getTimeLocal();
	server->run();
	control->runThreads();

	boost::thread *cli;
	// create cli thread that sends progress updatePort, control, qThreads);

	cli = new  boost::thread(boost::bind(&handle_cli, start, control));

	/*
	 *   Loop on condition variables waiting for 
	 *   cli shutdown or all inserters threads to finish
	 */ 
	//nop

	/* 
	 *  Wait for insertions to complete.  
	 *   if server was not asked to wait once insertion is done those
	 *   those threads will wrap up.
	 *  
	 *   Otherwise when CLI says to quit it will interupt threads 
	 *   and begin shutdown cleanly landing here at this join for 
	 *   threads.	
	 */

	// Has issue that cli needs to get interupted by last inserter.
	//  Possible solution of having inserters signal cli as they
	//  finish.  (aka interupt cli)
	cli->join();

	// mark end time
	// long stop = getTimeLocal();


	//std::cout << "Enter 'quit' or 'Quit' to shutdown server.\n";
	//std::string q = "";
	//while (q != "quit" && q != "Quit"){
	//	std::cin >> q;
	//}
	debug(30, "deleting server\n");
	delete server;
	debug(30, "deleting control\n");
	delete control;
	delete cli;
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
