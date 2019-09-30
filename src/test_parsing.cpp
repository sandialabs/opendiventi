//Tests the ability of the code to parse data across the various logFormats

#include "Bro_Parse.h"
#include "diventi.h"
#include "Control.h"
#include "DiventiStream.h"
#include "bro_functions.h"

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

	debug(0, "\nStarting test_parser\n");
	OPTIONS.sources[1] = new source("bro", "bro-data", 0, "", "suspiciousDir", "", 0);
	setUpFormat();
	std::list<logEntry *> results;

	Bro *func = new Bro();

	//DiventiStream in("small.log");
	// First line of small.log with empty numerical fields filled in arbitrarily, and no 0 values.
	/* Some fields/values removed since we do not care about them. Original lines:
	   "#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents";
	   "981927378.388876	CYYoei3hy4TjVFL5Gc	0.16.196.204	2208	216.190.59.150	80	tcp	none	15.0	256	128	RSTRH	t	1	r	1	1	1	40	(empty)";*/
	
	//First test Bro

	std::string format = "#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	duration	orig_bytes	resp_bytes	conn_state	orig_pkts	resp_pkts";
	std::string entry = "981927378.388876	CYYoei3hy4TjVFL5Gc	0.16.196.204	2208	216.190.59.150	80	tcp	15.0	256	128	RSTRH	1	1";
	char buf[123]; // For passing into logEntry
	
	BroFormat *lfBase = new BroFormat(format);
	memcpy(buf, entry.c_str(), entry.size());
	buf[entry.size()] = 0;
	func->parseBuf(buf, entry.size(), (logFormat **)&lfBase, &results);
	debug(10, "Format: %s\n", format.c_str());
	debug(10, "Entry: %s\n", entry.c_str());
	// debug(12, "Base: ts %li.%06li	uid %s	id.orig_p %d\n", leBase.ts / 1000000, leBase.ts % 1000000, leBase.uid.c_str(), leBase.id_orig_p);
	// Permute the base form and compare parsed entry results
	mirrorPermute(&format, &entry);
	BroFormat *lfPerm = new BroFormat(format);
	memcpy(buf, entry.c_str(), entry.size());
	func->parseBuf(buf, entry.size(), (logFormat **)&lfPerm, &results);
	debug(10, "Perm Format: %s\n", format.c_str());
	debug(10, "Perm Entry: %s\n", entry.c_str());
	// debug(12, "Perm: ts %li.%06li	uid %s	id.orig_p %d\n", lePerm.ts / 1000000, lePerm.ts % 1000000, lePerm.uid.c_str(), lePerm.id_orig_p);
	if (*results.front() != *results.back()){
		debug(30, "lePerm: %s\n\n", results.front()->toString().c_str());
		debug(30, "leBase: %s\n\n", results.back()->toString().c_str());
		debug(1, "Permutation: entry not equal\n");
		debug(0, "Test FAILED\n");
		exit(1);
	}

	// Truncate a field and compare parsed entry results
	format.erase(format.rfind('\t'));
	entry.erase(entry.rfind('\t'));
	debug(10, "Drop Format: %s\n", format.c_str());
	debug(10, "Drop Entry: %s\n", entry.c_str());
	BroFormat *lfDrop = new BroFormat(format);
	memcpy(buf, entry.c_str(), entry.size());
	func->parseBuf(buf, entry.size(), (logFormat **)&lfDrop, &results);
	// debug(12, "Drop: ts %li.%06li	uid %s	id.orig_p %d\n", leDrop.ts / 1000000, leDrop.ts % 1000000, leDrop.uid.c_str(), leDrop.id_orig_p);
	if (lfBase == lfDrop){
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
	BroFormat *lfDropPerm = new BroFormat(format);
	//In this case we don't want to compare with leBase so we need to save off leDrop
	BroEntry leDrop = *(dynamic_cast<BroEntry *>(results.back()));

	memcpy(buf, entry.c_str(), entry.size());
	func->parseBuf(buf, entry.size(), (logFormat **)&lfDropPerm, &results);
	// debug(12, "DropPerm: ts %li.%06li	uid %s	id.orig_p %d\n", leDropPerm.ts / 1000000, leDropPerm.ts % 1000000, leDropPerm.uid.c_str(), leDropPerm.id_orig_p);
	debug(10, "Drop Perm Format: %s\n", format.c_str());
	debug(10, "Drop Perm Entry: %s\n", entry.c_str());
	if (leDrop != *results.back()){
		debug(30, "leDrop: %s\n\n", leDrop.toString().c_str());
		debug(30, "leDropPerm: %s\n\n", results.back()->toString().c_str());
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