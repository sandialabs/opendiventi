#include "diventi.h"
#include "Key.h"
#include "Value.h"
#include "TokuHandler.h"
#include <cstdint>
#include <iostream>
#include <fstream>
#include <sys/time.h>

TokuHandler *toku;
uint64_t **inserted;	// Array of pointers - optimizes for writing from separate threads

// Timing is Linux specific
long calcNS(timespec& ts){
	return ts.tv_sec * 1000000000 + ts.tv_nsec;
}
long getTime(){
	auto now = std::chrono::steady_clock::now();
	return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
}

void insert(){
	Key *k, *rev;
	Value val(1,1,1,1,1,1,1,1);	// Throwaway value - can be same for all
	uint64_t count = 0;	// Local for write speed - it is quite significant
	inserted[/*TODO thread number*/] = &count;
	
	// TODO mutex to start all at once?
	for (/* TODO However many entries per thread*/){
		// TODO Generate a unique entry
		k = new Key(/* TODO origin port, timestamp, origin ip,
					  resp port, resp ip*/);
		rev = new Key(/* TODO same as last one */, true);	// With a flag for reversal
		toku->put(k, val);
		toku->put(rev, val);
		delete k;
		delete val;
	}
}

void sample(){
	// TODO Output to stdout or to a file?
	// TODO mutex to start all at once?
	try{
		while(1){	// Take samples
			inserted = 0;
			for (i = 0; i < inserters.size(); i++){
				inserted += inserters[i]->getNumInserted();
			}
			if (inserted - last > 0){
				out << inserted << ":" << getTime() << std::endl;	// Change to go to wherever the output should go
				last = inserted;
			}
			// About 1 sample/5 sec; this is an interrupt point
			boost::this_thread::sleep_for(boost::chrono::seconds(5));
		
		}
	} catch(boost::thread_interrupted){
		// TODO Clean up anything that needs to be cleaned up
	}
}

int main(){
	/* Program flow
	  Create several threads.
	  Each one does the following:
	  	for a specified number of entries:
	  		generate a unique entry
	  		insert it and its reversed form into the database
			increment a thread-local counter once
	
	  An additional thread should be concurrently sampling these counters
	  	at a rate of about once per 5 seconds
	 */
	boost::thread *sampler;
	boost::thread *inserters = new boost::thread[/* TODO number of threads */];

	inserted = new uint64_t*[/* TODO number of threads */]
	toku = new Tokuhandler();
	//TODO init threads (ideally boost to make it as similar as possible)
	// TODO init sampler
	// TODO mutex to start all at once?

	// To end, interrupt and join all threads
	sampler->interrupt();
	sampler->join();
	for (/* TODO number of threads */){
		inserters[i]->interrupt();
		inserters[i]->join();
	}

	return 0;
}