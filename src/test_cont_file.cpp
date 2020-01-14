#include "diventi.h"
#include "FileHandler.h"
#include "Bro_Parse.h"
#include "Control.h"

#include <boost/filesystem.hpp>


void clean(){
	// Cleanup
	unlink("./suspiciousDir/current/verySuspicious.txt");
	rmdir("./suspiciousDir/current");
	unlink("./suspiciousDir/verySuspicious.txt");
	rmdir("./suspiciousDir");
}

int main(int argc, char** argv){
	clean();
	if (argc < 2){
		debug_level = 0;
	} else{
		debug_level = atoi(argv[1]);
	}

	debug(0, "\nStarting test_cont_file\n");
	int a = argc;
	argc = a;
	char** b = argv;
	a = (int) **b;
	a = (int) **argv;
	source *tmp = new source();

	tmp->logFormat = "bro";
	tmp->tag = "bro-data";
	tmp->inputDir = "suspiciousDir";
	tmp->fNameFormat = "verySuspicious.txt";

	OPTIONS.sources[1] = tmp;
	OPTIONS.continuous = true;
	OPTIONS.dataBaseDir = "test";

	// setUpFormat();

	// Create the nested directory system
	boost::filesystem::path p0("suspiciousDir");
	boost::filesystem::create_directory(p0);
	boost::filesystem::path p1("suspiciousDir/current");
	boost::filesystem::create_directory(p1);

	// Create the file to be written to/read from
	std::ofstream outputFile("./suspiciousDir/current/verySuspicious.txt");
	
	// fields so that filehandler will accept this file, will be auto skipped
	// outputFile << "#fields\n"; 
	// outputFile.flush();

	FileHandler* f = new FileHandler;
	std::string* str;
	logFormat *lf;

	// Expect a line
	outputFile << "line 0\n";
	outputFile.flush();
	sleep(2);	// Give time for watcher to be notified

	debug(10, "getting line, expect line0\n");
	str = f->getNextLine(&lf);
	if (str == nullptr){
		debug(0, "TEST FAILED\n");
		debug(50, "Expected '%s', got nullptr\n", "line 0");
		clean();
		exit(1);
	} else if (*str != "line 0"){
		debug(0, "TEST FAILED\n");
		debug(50, "Expected '%s', got '%s'\n", "line 0", str->c_str());
		clean();
		exit(1);
	}
	delete str;

	debug(10, "getting line, expect nullptr\n");
	str = f->getNextLine(&lf);
	if (str != nullptr){
		debug(0, "TEST FAILED\n");
		debug(50, "Expected nullptr, got '%s'\n", str->c_str());
		clean();
		exit(1);
	}

	outputFile << "line 1\n";
	outputFile << "line 2";
	outputFile.flush();
	sleep(2);	// Give time for watcher to be notified

	debug(10, "getting line, expect line1\n");
	str = f->getNextLine(&lf);
	if (str == nullptr){
		debug(0, "TEST FAILED\n");
		debug(50, "Expected '%s', got nullptr\n", "line 1");
		clean();
		exit(1);
	} else if (*str != "line 1"){
		debug(0, "TEST FAILED\n");
		debug(50, "Expected '%s'\nGot '%s'\n", "line 1", str->c_str());
		clean();
		exit(1);
	}
	delete str;

	debug(10, "getting line, expect line2\n");
	str = f->getNextLine(&lf);
	if (str == nullptr){
		debug(0, "TEST FAILED\n");
		debug(50, "Expected '%s, got nullptr\n", "line 2");
		clean();
		exit(1);
	} else if (*str != "line 2"){
		debug(0, "TEST FAILED\n");
		debug(50, "Expected '%s'\nGot '%s'\n", "line 2", str->c_str());
		clean();
		exit(1);
	}
	delete str;


	// Move file and see if it tracks
	outputFile << "\nline 3";
	outputFile.flush();

	// Move the file
	boost::filesystem::path p2("suspiciousDir/current/verySuspicious.txt");
	boost::filesystem::path p3("suspiciousDir/verySuspicious.txt");
	boost::filesystem::rename(p2, p3);
	// Give time for watcher to discover new file
	sleep(2);

	debug(10, "getting line, expect line3\n");
	str = f->getNextLine(&lf);
	if (str == nullptr){
		debug(0, "TEST FAILED\n");
		debug(50, "Expected '%s', got nullptr\n", "line 3");
		clean();
		exit(1);
	}
	if (*str != "line 3"){
		debug(0, "TEST FAILED\n");
		debug(50, "Expected '%s'\nGot '%s'\n", "line 3", str->c_str());
		clean();
		exit(1);
	}
	delete str;

	str = f->getNextLine(&lf);
	if (str != nullptr){
		debug(0, "TEST FAILED\n");
		debug(50, "Expected nullptr, got '%s'\n", str->c_str());
		clean();
		exit(1);
	}
	clean();
	debug(0, "Test PASSED!\n");

}
