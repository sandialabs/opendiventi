#include "diventi.h"
#include "FileHandler.h"
#include "Bro_Parse.h"
#include "Control.h"

#include <boost/filesystem.hpp>

void cleanup(){
	unlink("./suspiciousDir/verySuspicious.txt");
	unlink("./suspiciousDir/conndefinitelyNotSuspicious.log");
	rmdir("./suspiciousDir");
}

int main(int argc, char* argv[]) {
	if (argc < 2){
		debug_level = 3;
	} else{
		debug_level = atoi(argv[1]);
	}
	debug(0, "\nStarting test_Watcher\n");
	int a = argc;
	argc = a;
	char** b = argv;
	a = (int) **b;
	a = (int) **argv;
	OPTIONS.sources[1] = new source("bro", "bro-data", 0, "", "suspiciousDir", "(.*\\/)?conn.*\\.log(\\.gz)?", 0);
	OPTIONS.continuous = true;
	OPTIONS.dataBaseDir = "test";

	setUpFormat();

	logFormat* lfp;

	boost::filesystem::path p("suspiciousDir");
	boost::filesystem::create_directory(p);

	FileHandler* f = new FileHandler;
	std::string* str;
	BroFormat lf;

	debug(25,"Testing first line\n");

	str = f->getNextLine(&lfp);
	if (str != nullptr){
		debug(0, "Test FAILED\n");
		debug(50, "Expected nullptr, got '%s'\n", str->c_str());
		cleanup();
		exit(1);
	}
	delete str;

	std::ofstream outputFile;
	outputFile.open("suspiciousDir/verySuspicious.txt");
	outputFile << "hi";
	outputFile.close();
	outputFile.open("./suspiciousDir/conndefinitelyNotSuspicious.log");
	outputFile << "hello\nsecond line";
	outputFile.close();


	sleep(1); //ensure that watcher has time to watch

	debug(25, "Testing second line\n");
	str = f->getNextLine(&lfp);
	if (str == nullptr){
		debug(0, "Test FAILED\n");
		debug(50, "Expected '%s', got nullptr\n", "hello");
		cleanup();
		exit(1);
	} else if (*str != "hello"){
		debug(0, "Test FAILED\n");
	 	debug(50, "Expected 'hello'\nGot '%s'\n", str->c_str());
	 	cleanup();
		exit(1);
	}
	delete str;

	debug(25, "Testing third line\n");
	str = f->getNextLine(&lfp);
	if (str == nullptr){
		debug(0, "Test FAILED\n");
		debug(50, "Expected '%s', got nullptr\n", "second line");
		cleanup();
		exit(1);
	} else if (*str != "second line"){
		debug(0, "Test FAILED\n");
		debug(50, "Expected 'second line'\nGot '%s'\n", str->c_str());
		cleanup();
		exit(1);
	}
	delete str;

	debug(25, "Testing fourth line\n");
	str = f->getNextLine(&lfp);
	if (str != nullptr){
		debug(0, "Test FAILED\n");
		debug(50, "Expected nullptr, got '%s'\n", str->c_str());
		cleanup();
		exit(1);
	}
	delete str;

	delete f;
	cleanup();

	debug(0, "Test PASSED!\n");
}