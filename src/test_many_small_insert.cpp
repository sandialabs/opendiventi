#include "diventi.h"

#include "Control.h"
#include "TokuHandler.h"

#include <boost/thread.hpp>
#include <boost/chrono.hpp>
#include <boost/filesystem.hpp>



int main(int argc, char* argv[]) {
	if (argc < 2){
		debug_level = 0;
	} else{
		debug_level = atoi(argv[1]);
	}

	debug(0, "\nStarting test_many_small_insert\n");
	int a = argc;
	argc = a;
	char** b = argv;
	a = (int) **b;
	a = (int) **argv;
	OPTIONS.dataBaseDir = "test";
	source *tmp = new source();

	tmp->logFormat = "bro";
	tmp->tag = "bro-data";
	tmp->inputDir = "many_small";
	tmp->fNameFormat = "small.log";

	OPTIONS.sources[1] = tmp;

	Control* control = new Control(1);
	control->runThreads();
	debug(10, "inserter ran\n");

	delete control;
	boost::filesystem::path processed(std::string(OPTIONS.dataBaseDir) + "/.Processed");
	boost::filesystem::remove_all(processed);
	debug(0, "Test PASSED!\n"); //it would have crashed had it failed
}