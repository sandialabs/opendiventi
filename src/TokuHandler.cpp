#include "TokuHandler.h"

#include "diventi.h"
#include "KeyValuePair.h"

#include <sys/stat.h>
#include <sys/sysinfo.h>

#include "Basic_Value.h"
#include "Mon_Value.h"
#include "Bro_Value.h"
#include "NetV9_Value.h"
#include "Net_Value.h"

#include "IP_Key.h"
#include "Basic_Key.h"


/*
	Each value has a byte which identifies which source was used to insert it.
	Reading this byte allows us to use the same data format to print out the information.
	We do this by creating a Value object which is dependent upon the unique data format.
*/

Value *getValueFromSource(DBT* dbt) {
	uint8_t src = (uint8_t) ((char *)dbt->data)[0];
	if( OPTIONS.sources[src] != nullptr ) {
		std::string format = OPTIONS.sources[src]->logFormat;
			if( format == "bro") {
				return new Bro_Value(dbt);
			}
			else if( format == "mon"){
				return new Mon_Value(dbt);
			}
			else if (format == "NetV5" || format == "netAscii") {
				return new Net_Value(dbt);
			}
			else if (format == "NetV9"){
		        return new NetV9_Value(dbt);
		        }
			else if (format == "basic"){
				return new Basic_Value(dbt);
			}
			//NEWFORMAT Add new ifs for new formatting types here
			else {
				debug(1, "WARNING: Unrecognized logFormat in source %u, defaulting to bro\n", src);
				return new Bro_Value(dbt);
			}
	}
	else {
		debug(1, "WARNING: Source %u does not exist for this value, skipping\n", src);
		return nullptr;
	}
}

// Basic function to return different key types based on the keyCompare function
Key *getKeyFromCompare(DBT *dbt) {
	if( keyCompare == IPv4_KeyCompare ) {
		return new IP_Key(dbt);
	}
	else if( keyCompare == BASIC_KeyCompare ) {
		return new Basic_Key(dbt);
	}
	else {
		diventi_error("ERROR: keyCompare doesn't match ipv4 or basic");                
        return new IP_Key(dbt);
	}
}

TokuHandler::TokuHandler() {
	//char dbfile[MAX_DB_FILENAME_LENGTH] = {'\0'};
	char* dbfile = (char*) calloc(MAX_DB_FILENAME_LENGTH, sizeof(char));
	char* dbdir = (char*) calloc(MAX_ENV_DIRNAME_LENGTH, sizeof(char));// = {'\0'};

	strncpy(dbfile, DB_FILE, MAX_DB_FILENAME_LENGTH);
	dbfile[MAX_DB_FILENAME_LENGTH - 1] = '\0';

	strncpy(dbdir, DEFAULT_DIR, MAX_ENV_DIRNAME_LENGTH);
	dbdir[MAX_ENV_DIRNAME_LENGTH - 1] = '\0';

	int r;

	int envOpenFlags = DB_PRIVATE|DB_INIT_MPOOL|DB_INIT_LOCK;
	int dbOpenFlags = DB_CREATE;

	db_env_set_direct_io(OPTIONS.directIo); //DEFAULT FALSE


	if(OPTIONS.dataBaseDir != nullptr) {
		strncpy(dbdir, OPTIONS.dataBaseDir, MAX_ENV_DIRNAME_LENGTH);
		dbdir[MAX_ENV_DIRNAME_LENGTH - 1] = '\0';
	}

	if(OPTIONS.create) { //DEFAULT TRUE
		envOpenFlags |= DB_CREATE;
		r = mkdir(dbdir, S_IRWXU|S_IRWXG);
		if(r != 0 && errno != EEXIST) {
			diventi_error("Error creating dbdir %d: %s\n", 
				errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	if(OPTIONS.tokuThreaded) { //DEFAULT TRUE
		envOpenFlags |= DB_THREAD;
	}


	r = db_env_create(&env, 0);
	if(r != 0) {
		diventi_error("Error creating db environment. %d: %s\n", r, db_strerror(r));
		exit(EXIT_FAILURE);
	}

	env->set_errfile(env, stderr);

	r = env->set_default_bt_compare(env, keyCompare);
	if(r != 0) {
		diventi_error("Error setting comparator. %d: %s\n", r, db_strerror(r));
		exit(EXIT_FAILURE);
	}

	// Set the cachesize to fifty percent of available main memory
	#define GB 1000000000
	struct sysinfo info;
	if (sysinfo(&info) != 0) {
		diventi_error("Failed to get total main memory size %d: %s\n",errno, strerror(errno));
	}
	uint64_t memory_size = info.totalram;
	debug(10, "total ram = %lu\n", memory_size);
	// divide by 2GB in order to get half of the GBs of memory
	// Add one to round up
	r = env->set_cachesize(env, memory_size/(GB*2), 0, 1);
	if(r != 0) {
		diventi_error("Error setting cache size. %d: %s\n", r, db_strerror(r));
		exit(EXIT_FAILURE);
	}

	// Sets the percent of FS free space before toku throws and error as 1%
	r = env->set_redzone(env, 1);
	if(r != 0) {
		diventi_error("Error setting red zone. %d: %s\n", r, db_strerror(r));
		exit(EXIT_FAILURE);
	}

	r = env->open(env, dbdir, envOpenFlags, S_IRWXU|S_IRWXG);
	if(r != 0) {
		diventi_error("Error opening environment. %d: %s\n", r, db_strerror(r));
		exit(EXIT_FAILURE);
	}

	if((r = db_create(&db, env, 0)) != 0) {
		diventi_error("Error creating db. %d: %s\n", r, db_strerror(r));
		exit(EXIT_FAILURE);
	}

	// Set the fanout, or the number of children each internal node has
	if((r = db->set_fanout(db, OPTIONS.tokuFanout)) != 0) {
		diventi_error("Error setting fanout for db. %d: %s\n", r, db_strerror(r));
		exit(EXIT_FAILURE);
	}

	// Set the compression method, options are 
	//		TOKU_NO_COMPRESSION
	//		TOKU_SNAPPY_METHOD
	//		TOKU_ZLIB_METHOD
	//		TOKU_QUICKLZ_METHOD
	//		TOKU_LZMA_METHOD
	//		TOKU_ZLIB_WITHOUT_CHECKSUM_METHOD
	//		TOKU_DEFAULT_COMPRESSION_METHOD
	//		TOKU_FAST_COMPRESSION_METHOD
	//		TOKU_SMALL_COMPRESSION_METHOD
	if((r = db->set_compression_method(db, OPTIONS.tokuCompression)) != 0) {
		diventi_error("Error setting compression for db. %d: %s\n", r, db_strerror(r));
		exit(EXIT_FAILURE);
	}

	// Set the pagesize, or the amount of buffered data before flushing or splitting required
	if((r = db->set_pagesize(db, OPTIONS.tokuPagesize)) != 0) {
		diventi_error("Error setting pagesize for db. %d: %s\n", r, db_strerror(r));
		exit(EXIT_FAILURE);
	}

	if((r = db->open(db, NULL, dbfile, NULL, DB_BTREE,
		dbOpenFlags, S_IRUSR|S_IWUSR|S_IRGRP)) != 0) {
		diventi_error("Error opening db. %d: %s\n", r, db_strerror(r));
		exit(EXIT_FAILURE);
	}


	free(dbfile);
	free(dbdir);

	// Print out the db setup
	uint32_t gbytes = 0;
	uint32_t bytes = 0;
	int ncache = 0;
	if((r = env->get_cachesize(env, &gbytes, &bytes, &ncache)) != 0) {
		debug(10, "WARNING: failed to get cache size %d: %s\n", r, db_strerror(r));
	}

	TOKU_COMPRESSION_METHOD compression = TOKU_NO_COMPRESSION;
	if((r = db->get_compression_method(db, &compression)) != 0) {
		debug(10, "WARNING: failed to get toku compression %d: %s\n", r, db_strerror(r));
	}

	uint32_t fanout = 0;
	if((r = db->get_fanout(db, &fanout)) != 0) {
		debug(10, "WARNING: failed to get fanout %d: %s\n", r, db_strerror(r));
	}

	uint32_t pagesize = 0;
	if((r = db->get_pagesize(db, &pagesize)) != 0) {
		debug(10, "WARNING: failed to get pagesize %d: %s\n", r, db_strerror(r));
	}

	debug(10, "TokuDB initialized with the following settings:\n");
	debug(10, "cachesize = %i caches of size: %uGB %ubytes\n", ncache, gbytes, bytes);
	debug(10, "compression method = %u\n", compression);
	debug(10, "fanout(number of children) = %u\n", fanout);
	debug(10, "pagesize(size of buffer) = %u\n", pagesize);
}

TokuHandler::~TokuHandler() {
	int r = db->close(db, 0);
	if(r != 0) {
		diventi_error("Error closing db. %d: %s", r, db_strerror(r));
	}
	debug(90, "DB closed.\n");

	r = env->close(env, 0);
	if(r != 0) {
		diventi_error("Error closing db. %d: %s", r, db_strerror(r));
	}
	debug(90, "ENV closed.\n");
}

// The cleaner flushes data out of blocks, we enable this thread at a specified number of insertions
void TokuHandler::enableCleaner() {
	int r;
	
	// Set the delay between each run of the cleaner threads (0 means disabled)
	r = env->cleaner_set_period(env, OPTIONS.tokuCleanerPeriod);
	if(r != 0) {
		diventi_error("Error setting cleaner period %d: %s\n", r, db_strerror(r));
		exit(EXIT_FAILURE);
	}

	// Set the number of nodes the cleaners will inspect on each run
	r = env->cleaner_set_iterations(env, OPTIONS.tokuCleanerIterations);
	if(r != 0) {
		diventi_error("Error setting cleaner iterations %d: %s\n", r, db_strerror(r));
		exit(EXIT_FAILURE);
	}

	uint32_t period;
	r = env->cleaner_get_period(env, &period);
	if(r != 0) {
		debug(10, "WARNING: failed to get cleaner period %d: %s\n", r, db_strerror(r));
	}

	uint32_t iterations;
	r = env->cleaner_get_iterations(env, &iterations);
	if(r != 0) {
		debug(10, "WARNING: failed to get cleaner iterations %d: %s\n", r, db_strerror(r));
	}
	debug(10, "changed cleaner to:\n");
	debug(10, "cleaner period = %u\n", period);
	debug(10, "cleaner iterations = %u\n", iterations);
}

bool TokuHandler::put(KeyValuePair* pair) {
	bool ret = put(*pair->getKey(), *pair->getValue());
	delete pair->getKey();
	delete pair->getValue();
	delete pair;
	return ret;
}

//void TokuHandler::put(Key key, Value value) {
bool TokuHandler::put(const Key & key, const Value & value) {
	int r = db->put(db, NULL, key.getDBT(), value.getDBT(), 0);
	if(r != 0) {
		diventi_error("Error inserting. %d: %s\n", r, db_strerror(r));
		return false;
	}
	return true;
}

/*
	Retuns stored KeyValuePairs based on a range of possible key values
		There can be none, one, or many results all of which are stored into
		ret and returned if there are no errors in the process
	Called by QuerySession::resolveQuery
	Is it possible to have the cursor check both the orig_ip and resp_ip (Is this actually a problem? YES)
		Making query twice as long is better than making the amount of data stored twice as much
*/
std::vector<KeyValuePair>* TokuHandler::get(Key* start, Key* end) {
	int r; //for error catching purposes
	std::vector<KeyValuePair>* ret = new std::vector<KeyValuePair>(); //what will eventually be returned

	DBC* cursor = nullptr;
	DBT* cursorValue = new DBT();
	cursorValue->flags |= DB_DBT_MALLOC;

	DBT* cursorKey = new DBT();
	DBT* startDBT = start->getDBT();
	memcpy(cursorKey, startDBT, sizeof(DBT));
	cursorKey->flags |= DB_DBT_MALLOC; //set flag so that db will allocate memory for the returned key
	r = db->cursor(db, nullptr, &cursor, 0); //set up the cursor for moving through the db
	if(r != 0) { //error checking
		diventi_error("Error getting cursor. %d: %s", r, db_strerror(r));
		throw std::runtime_error("Error getting cursor.");
	}

	//this is leaking memory
	r = cursor->c_get(cursor, cursorKey, cursorValue, DB_SET_RANGE);
	if(r != 0) { //even more error checking
		if(r != DB_NOTFOUND) {
			diventi_error("Error setting range. %d: %s", r, db_strerror(r));
			throw std::runtime_error("Error setting range.");
		} else {
			Key *key = getKeyFromCompare(cursorKey);
			std::string currentString = key->toString();
			debug(90, "Empty query. Start:\n%s", currentString.c_str());
			delete key;
		}
		r = cursor->c_close(cursor);
		if(r != 0) { //error checking
			debug(90, "Cursor failed to close");
		}
		return ret;
	}
	//passed all the error checking, cursor now set up correctly
	bool cont = true;

	while(cont) {
		debug(95, "TokuHandler entering while\n");
		if(keyCompare(db, end->getDBT(), cursorKey) < 0) {
			debug(95, "TokuHandler got to the end dbt.\n");
			cont = false;
			continue;
		} else {
			DBT* keyCopy = new DBT();
			DBT* valueCopy = new DBT();
			memcpy(keyCopy, cursorKey, sizeof(DBT));
			memcpy(valueCopy, cursorValue, sizeof(DBT));
			Key *tempKey = getKeyFromCompare(keyCopy);
			Value *tempValue = getValueFromSource(valueCopy);

			if (tempValue != nullptr) {
				// KeyValuePair* out = new KeyValuePair(tempKey, tempValue);
				debug(95, "TokuHandler pushing result into vector\n%s\n%s\n", tempKey->toString().c_str(), tempValue->toString().c_str());
				ret->push_back(KeyValuePair(*tempKey, *tempValue)); //temp key and temp value to be deleted by querySession later
				delete keyCopy;
				delete valueCopy;
			}

			//This is leaking memory
			r = cursor->c_get(cursor, cursorKey, cursorValue, DB_NEXT);
			if(r != 0) {
				if(r != DB_NOTFOUND) {
					diventi_error("Error incrementing cursor. %d: %s", r, db_strerror(r));
				} else {
					Key *endKey = getKeyFromCompare(end->getDBT());
					Key *curKey = getKeyFromCompare(cursorKey);
					std::string endString = endKey->toString();
					std::string currentString = curKey->toString();
					debug(95, "Fell off the end of the db?. Cursor:\n%sEnd:\n%s\n", currentString.c_str(), endString.c_str());
					delete endKey;
					delete curKey;
					break;
				}
			}
		}
	}
	r = cursor->c_close(cursor);
	if(r != 0) {
		debug(90, "Cursor failed to close");
	}
	delete cursorKey;
	delete cursorValue;
	return ret;
}
	// TOKU_DB_FRAGMENTATION_S frag;
	// if((r = db->get_fragmentation(db, &frag)) != 0) {
	// 	debug(0, "Error fragmentation. %d: %s\n", r, db_strerror(r));
	// }

	// debug(0, "file size bytes: %lu\n", frag.file_size_bytes);
	// debug(0, "data bytes: %lu\n", frag.data_bytes);
	// debug(0, "data blocks: %lu\n", frag.data_blocks);
	// debug(0, "checkpoint bytes additional: %lu\n", frag.checkpoint_bytes_additional);
	// debug(0, "checkpoint blocks additional: %lu\n", frag.checkpoint_blocks_additional);
	// debug(0, "unused bytes: %lu\n", frag.unused_bytes);
	// debug(0, "unused blocks: %lu\n", frag.unused_blocks);
	// debug(0, "size of largest unused block: %lu\n\n", frag.largest_unused_block);

// Function to get information about the current status of the database and print it to a file
// Will hopefully be useful for debugging performance issues
// ewest - 0
std::string TokuHandler::DBStat(std::fstream *file) {
	int r;

	DB_BTREE_STAT64 bt;
	if((r = db->stat64(db, NULL, &bt)) != 0) {
		debug(0, "Error db stats. %d: %s\n", r, db_strerror(r));
	}
	*file << "estimated number of keys: " << bt.bt_nkeys << "\n";
	*file << "number of kvs pairs: " << bt.bt_ndata << "\n";
	*file << "size of the kvs pairs: " << bt.bt_dsize << "\n";
	*file << "size of the file: " << bt.bt_fsize << "\n";
	
	uint64_t num_rows;
	if((r = env->get_engine_status_num_rows(env, &num_rows)) != 0) {
		debug(0, "Error status_num_rows. %d: %s\n", r, db_strerror(r));
	}

	int status_size = 128*num_rows;
	char * status = (char *) malloc(status_size);
	env->get_engine_status_text(env, status, status_size);
	if((r = env->get_engine_status_num_rows(env, &num_rows)) != 0) {
		debug(0, "Error engine_status. %d: %s\n", r, db_strerror(r));
	}
	*file << status << "\n";

	*file << "creation time: " << bt.bt_create_time_sec << "\n";
	*file << "time of last serialization: " << bt.bt_modify_time_sec << "\n";
	*file << "time of last verification: " << bt.bt_verify_time_sec << "\n";

	return "";
}
