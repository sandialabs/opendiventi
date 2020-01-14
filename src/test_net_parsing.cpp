//Tests the ability of the code to parse data across the various logFormats

#include "Net_Parse.h"
#include "diventi.h"
#include "Control.h"
#include "DiventiStream.h"
#include "netAscii_functions.h"

#include <vector>
#include <boost/algorithm/string.hpp>
#include <stdio.h>
#include <cstdlib>

// Permutes an entry-field pair identically
bool mirrorPermute(std::string *f, std::string *e){
	std::vector<std::string> ftoks, etoks;
	std::string tmp;
	unsigned int i, pos;
	srand(time(NULL));
	boost::split(ftoks, *f,  boost::is_any_of(std::string("\t")));
	boost::split(etoks, *e,  boost::is_any_of(std::string("\t")));
	// Reconstruct strings
	*f = "#fields	";
	*e = "";
	debug(40, "ftoks: %li elements\tetoks: %li elements\n", ftoks.size(), etoks.size());

	// Fill in the i'th position. Unpicked elements go to the back so we can choose from them easily.
	for (i = 1; i < ftoks.size(); i++){
		pos = (rand() % (ftoks.size() - i)) + i;	// Random element not already selected
		debug(40, "Swapping %d with %d\n", i, pos);

		tmp = ftoks[pos];
		ftoks[pos] = ftoks[i];
		ftoks[i] = tmp;
		debug(40, "passed first swap\n");
		tmp = etoks[pos - 1];
		etoks[pos - 1] = etoks[i - 1];
		etoks[i - 1] = tmp;
		debug(40, "passed second swap\n");
		*f = *f + ftoks[i] + "\t";
		*e = *e + etoks[i - 1] + "\t";
		debug(40, "Current format: '%s'\n", f->c_str());
		debug(40, "Current entry:  '%s'\n", e->c_str());
	}

	if (ftoks.size() > 1){
		f->erase(f->rfind('\t'));
		e->erase(e->rfind('\t'));
	}
	return true;
}

int main(int argc, char **argv){
	if (argc < 2){
		debug_level = 0;
	} else{
		debug_level = atoi(argv[1]);
	}

	NetAscii *func = new NetAscii();

	debug(0, "\nStarting test_parser\n");
	//Now test for netAscii
	source *tmp = new source();

	tmp->logFormat = "netAscii";
	tmp->tag = "netascii";
	tmp->inputDir = "suspiciousDir";

	OPTIONS.sources[1] = tmp;
	// setUpFormat();
	std::list<logEntry *> results;

	std::string format = "#fields	ts	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	duration	bytes	tcp_flags	pkts";
	std::string entry = "981927378.388876	0.16.196.204	2208	216.190.59.150	80	TCP	15.0	128	UAP..	1";
	char buf[123]; // For passing into logEntry

	NetFormat *lfBase = new NetFormat(format);
	memcpy(buf, entry.c_str(), entry.size());
	buf[entry.size()] = 0;
	func->parseBuf(buf, entry.size(), (logFormat **)&lfBase, &results);
	debug(10, "Format: %s\n", format.c_str());
	debug(10, "Entry: %s\n", entry.c_str());
	// debug(12, "Base: ts %li.%06li	uid %s	id.orig_p %d\n", leBase.ts / 1000000, leBase.ts % 1000000, leBase.uid.c_str(), leBase.id_orig_p);
	// Permute the base form and compare parsed entry results
	mirrorPermute(&format, &entry);
	NetFormat *lfPerm = new NetFormat(format);
	memcpy(buf, entry.c_str(), entry.size());
	func->parseBuf(buf, entry.size(), (logFormat **)&lfPerm, &results);
	debug(10, "Perm Format: %s\n", format.c_str());
	debug(10, "Perm Entry: %s\n", entry.c_str());
	// debug(12, "Perm: ts %li.%06li	uid %s	id.orig_p %d\n", lePerm.ts / 1000000, lePerm.ts % 1000000, lePerm.uid.c_str(), lePerm.id_orig_p);
	if (*results.front() != *results.back()){
		debug(30, "leBase: %s\n\n", results.front()->toString().c_str());
		debug(30, "lePerm: %s\n\n", results.back()->toString().c_str());
		debug(1, "Permutation: entry not equal\n");
		debug(0, "Test FAILED\n");
		exit(1);
	}
	// Truncate a field and compare parsed entry results
	format.erase(format.rfind('\t'));
	entry.erase(entry.rfind('\t'));
	debug(10, "Drop Format: %s\n", format.c_str());
	debug(10, "Drop Entry: %s\n", entry.c_str());
	NetFormat *lfDrop = new NetFormat(format);
	memcpy(buf, entry.c_str(), entry.size());
	func->parseBuf(buf, entry.size(), (logFormat **)&lfDrop, &results);
	// debug(12, "Drop: ts %li.%06li	uid %s	id.orig_p %d\n", leDrop.ts / 1000000, leDrop.ts % 1000000, leDrop.uid.c_str(), leDrop.id_orig_p);
	if (lfBase == lfDrop){
		debug(1, "lfDrop: %s", lfDrop->toString().c_str());
		debug(1, "lfBase: %s", lfBase->toString().c_str());
		debug(1, "Drop: format equal\n");
		debug(0, "Test FAILED\n");
		exit(1);
	}
	if (*results.front() == *results.back()){
		debug(30, "leBase: %s\n\n", results.front()->toString().c_str());
		debug(30, "leDrop: %s\n\n", results.back()->toString().c_str());
		debug(1, "Drop: entry equal\n");
		debug(0, "Test FAILED\n");
		exit(1);
	}

	// Permute the truncated form and compare parsed entry results
	mirrorPermute(&format, &entry);
	NetFormat *lfDropPerm = new NetFormat(format);
	//In this case we don't want to compare with leBase so we need to save off leDrop
	NetEntry leDrop = *(dynamic_cast<NetEntry *>(results.back()));

	memcpy(buf, entry.c_str(), entry.size());
	func->parseBuf(buf, entry.size(), (logFormat **)&lfDropPerm, &results);
	// debug(12, "DropPerm: ts %li.%06li	uid %s	id.orig_p %d\n", leDropPerm.ts / 1000000, leDropPerm.ts % 1000000, leDropPerm.uid.c_str(), leDropPerm.id_orig_p);
	debug(10, "Drop Perm Format: %s\n", format.c_str());
	debug(10, "Drop Perm Entry: %s\n", entry.c_str());
	if (leDrop != *results.back()){
		debug(30, "leDrop: %s\n\n", leDrop.toString().c_str());
		debug(30, "leDropPerm: %s\n\n",results.back()->toString().c_str());
		debug(1, "Drop permutation: entry not equal\n");
		debug(0, "Test FAILED\n");
		exit(1);
	}
	debug(0, "Test PASSED\n");
	delete lfBase;
	delete lfPerm;
	delete lfDrop;
	delete lfDropPerm;
	delete func;
}