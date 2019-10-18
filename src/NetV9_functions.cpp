#include "diventi.h"
#include "IP_Key.h"

#include "NetV9_Value.h"
#include "NetV9_Parse.h"
#include "KeyValuePair.h"
#include "DiventiStream.h"
#include "SyslogHandler.h"
#include "NetV9_functions.h"

#include <vector>
#include <boost/algorithm/string.hpp>
#include <stdio.h>
#include <cstdlib>
#include <sstream>
#include <map>

//-----------------------
//Functions for extracting data from the netflow header buffer
static uint16_t versionHandler(uint8_t *s) {
	uint16_t ver = 0;
	for( int j = 0; j < 2; j++ ) {
		ver += (uint8_t)s[VERSION+j] << (8*(1-j));
	}
	debug(75, "version: %u\n", ver);
	return ver;
}

static uint16_t countHandler(uint8_t *s) {
	uint16_t count = 0;
	for( int j = 0; j < 2; j++ ) {
		count += (uint8_t)s[FLOWS+j] << (8*(1-j));
	}
	debug(75, "flowNum set: %u\n", count);
	return count;
}

// static uint32_t uptimeHandler(uint8_t *s) {
// 	uint32_t uptime = 0;
// 	for( int j = 0; j < 4; j++ ){
// 		uptime += (uint8_t)s[UPTIME+j] << (8*(3-j));
// 	}
// 	debug(75, "sysTime set: %u\n", uptime);
// 	return uptime;
// }

// static uint32_t nanoSecHandler(uint8_t *s) {
// 	uint32_t nano = 0;
// 	for( int j = 0; j < 4; j++ ){
// 		nano += (uint8_t)s[UPTIME+j] << (8*(3-j));
// 	}
// 	debug(75, "nanoSecTime set: %u\n", nano);
// 	return nano;
// }

// static uint32_t sequenceHandler(uint8_t *s) {
// 	uint32_t seq = 0;
// 	for( int j = 0; j < 4; j++ ){
// 		seq += (uint8_t)s[SEQ+j] << (8*(3-j));
// 	}
// 	 //PackageSeq = seq;
// 	debug(75, "sequence number: %u\n", seq);
// 	return seq;
// }

// static uint32_t SourceIDHandler(uint8_t *s) {
// 	uint32_t id = 0;
// 	for( int j = 0; j < 4; j++ ){
// 		id += (uint8_t)s[S_ID+j] << (8*(3-j));
// 	}
// 	// sID = id;
// 	debug(75, "Source ID: %u\n", id);
// 	return id;
// }



//-----------------------
//Functions for extracting data from the beginning of flowSets

static uint16_t FlowIDHandler(uint8_t *s) {
	int16_t id = 0;
	for( int j = 0; j < 2; j++ ) {
		id += (uint8_t)s[NetV9_Format::F_ID+j] << (8*(1-j));
	}
	return id;
}

static uint16_t LengthHandler(uint8_t *s) {
	int16_t len = 0;
	for( int j = 0; j < 2; j++ ) {
		len += (uint8_t)s[NetV9_Format::LENG+j] << (8*(1-j));
	}
	return len;
}

//------------------------------------
//deconstruction
NetV9::~NetV9() {
	debug(50, "Deleting NetV9\n");
	for (auto const& x : templates) {
		delete x.second;
	}
	for (auto const& x : oldTemplates) {
		delete x.second;
	}
	// for (auto const& x : data_buffer) {
	// 	delete x.second;
	// }
}

bool NetV9::parseFileFormat(std::string /*file*/, logFormat **format) {
	debug(60, "identified netflow\n");
	std::string line;
	*format = createFormat(line);
	return true;
}


/*
Function that returns the counts of verious errors
*/

std::string NetV9::getStats() {
	std::string stats = "Counts of Dropped records:\nNumber of Dropped : Likely Reason\n";
	stats += std::to_string(numDropIPv6) + " : IPv6\n";
	stats += std::to_string(numDropVer) + " : Bad Version\n";
	stats += std::to_string(numDropTemplate) + " : Missing Template -- flows dropped: " + std::to_string(numDropTemplateFlows) + std::string("\n");
	stats += std::to_string(numDropShort) + " : Packet too short -- flows dropped: " + std::to_string(numFlowDropShort) + std::string("\n");
	return stats;
}

// static int handleDataBuffer(uint8_t *buf, uint32_t size, logFormat **f, std::list<logEntry *> *results) {
// 	uint32_t position = 0;
// 	uint32_t number = 0;
// 	while( position < size ) {
// 		int length = LengthHandler((uint8_t *)buf + position);
// 		number += functions->parseBuf((char *)buf+position, length, f, results);
// 		position += length;
// 	}
// 	return number;
// }

//Function to parse the flowSets found within a packet
//It will receive one flowSet and will parse that
//**f for new version
int NetV9::parseBuf(char * buf, int size, logFormat **f, std::list<logEntry *> *results){
	uint16_t number = 0;
	int32_t flowNum = 0;
	//uint32_t sysTime = 0;
	//If there are flows in the buffer which we can parse... do that now
	
	// if( data_buffer.count(buffer_id) == 1) {
	// 	debug(0, "Inserting from data_buffer, id = %u\n", buffer_id);

	// 	uint32_t size = data_buffer[buffer_id]->size - data_buffer[buffer_id]->avail_size;
	// 	uint8_t b[size];
	// 	memcpy(b, data_buffer[buffer_id]->buffer, size);

	// 	delete data_buffer[buffer_id];
	// 	data_buffer.erase(buffer_id);

	// 	number += handleDataBuffer(b, size, f, results);
	// }
	//RECORD HEADER PARSING
	flowNum = countHandler((uint8_t *)buf);
	//sysTime = uptimeHandler((uint8_t *)buf);
	//sequenceHandler((uint8_t *)buf);
	//SourceIDHandler((uint8_t *)buf);
	uint16_t id;
	int position = 20;
	while(flowNum > 0) {
		debug(70, "flowNum: %u, position: %u out of: %u\n", flowNum, position, size);
		int begin = position;
		//FLOWSETS
		//Now read the first FlowSet in the packet
		// slh->getNextBytes(buf, 4, fp);

		//FLOW SET HEADER PARSING
		id = FlowIDHandler((uint8_t *)buf+position);
		uint16_t length = LengthHandler((uint8_t *)buf+position); //The length includes the bytes we've already gotten
		if( length + begin > size ) {
			debug(5, "The record isn't as large enough for flowSet(cur id = %u) of length: %u, need %u more. SKIPPING. Could also be because of earlier error\n", id, length, (length + begin) - size);
			position = size;
			numDropShort += 1;
			numFlowDropShort += flowNum;
			break;
			//counter for this error
		}
		debug(60, "length of flowSet: %u\n", length);
		position += 4;
		//while the difference between the beginning of flowSet and current position is less than length of flowSet
		while((position - begin) < length) {
			debug(70, "length = %u, relative position = %u, position = %u, out of = %u\n", length, position - begin, position, size);
			//FLOWS
			if( id == 0 ) {
				//Template, pass to NetV9_Parse to create a format for this template
				debug(60, "Template\n");
				uint16_t tID = (buf[position + NetV9_Format::T_ID] << 8) + buf[position + NetV9_Format::T_ID + 1];
				NetV9_Format *copy = nullptr;
				uint16_t temp;
				if(templates.count(tID) == 1) {
					//about to replace this pointer but other threads might be using it
					//So, put it in oldTemplates and delete what's in there if necessary
					if(oldTemplates.count(tID) == 1) {
						copy = oldTemplates[tID];
					}
					oldTemplates[tID] = templates[tID];
					//if this thing we're replacing is the (most recently used)MRU template
					//then set MRU to zero to 'clear' it
				}
				// if( data_buffer.count(tID) == 1) {
				// 	buffer_id = tID;
				// }
				try {
					templates[tID] = new NetV9_Format((uint8_t *)buf + position, &temp);
				} catch( std::exception &e) {
					debug(5, "Segfault caught when creating template, skipping this record. Error: %s\n", e.what());
					position = size; //-4 because length includes flowSet header
					flowNum = 0;
					//If we can revert back to the old template
					if(oldTemplates.count(tID) == 1) {
						templates[tID] = oldTemplates[tID];
						oldTemplates.erase(tID);
					}
					else {
						//ensure no one tries to use this current one
						//if we can't revert back to something safe;
						templates.erase(tID);
					}
					break;
				}
				//if a copy was found delete it
				// MRU_templateID = (tID == MRU_templateID)? 0: MRU_templateID;
				delete copy;
				//temp is the amount of data read by the constructor and 4 is the size of the header
				position += temp + 4;
				
			}
			else if( id == 1 ) {
				//Options Template... for now skip it
				uint16_t count1 = (buf[position+2] << 8) + buf[position+3];
				uint16_t count2 = (buf[position+4] << 8) + buf[position+5];
				debug(60, "Options template. count1: %u count2: %u\n", count1, count2);
				position += count1 + count2 + 6;
			}
			else {
				debug(60, "data\n");
				// if we need to get a new template and we have it then set f to that template
				// 	for use now and later
				if (/*id != MRU_templateID &&*/ templates.count(id) == 1) {
					*f = (templates[id]); //This is currently unnecessary
					// MRU_template = (templates[id]);
					// MRU_templateID = id;
				}
				else if (templates.count(id) != 1){
				// 	//we don't currently have the ability to parse this data
				// 	//Stick it in the buffer
				// 	if( data_buffer.count(id) != 1) {
				// 		//There is no buffer for this id yet so make one
				// 		debug(0, "Made data_buffer id = %u\n", id);
				// 		data_buffer[id] = new data_buf();
				// 	}
				// 	//add the data to the relevant data_buffer
				// 	if( data_buffer[id]->avail_size >= uint(size)) {
				// 		debug(0, "adding to data buffer\n");
				// 		memcpy(data_buffer[id]->buffer + data_buffer[id]->position, buf, size);
				// 		data_buffer[id]->position += size;
				// 		data_buffer[id]->avail_size -= size;
				// 	}
					// else {
						debug(10, "Dropped a data flow because we don't have a template for it!, id = %u\n", id);
					// }
					//Drop the record
					numDropTemplateFlows += flowNum;
					numDropTemplate += 1;
					position = size;
					flowNum = 0; //= 0 because there is no way currently to tell how many flows are in this record, so we don't know what else to parse
					break;
				}
				//NetV9_Format *fp = MRU_template;
				NetV9_Format *fp = dynamic_cast<NetV9_Format *>(*f);
				NetV9_Entry *e = new NetV9_Entry();
				for (int i = 0; i < fp->lastToken; i++) {
					(*(fp->fieldHandler[i]))(e,(char *)(buf+fp->locations[i] + position));
				}
				debug(100, "totalSize: %u\n", fp->totalSize);
				position += fp->totalSize;
				debug(70, "Inserted logEntry: %s", e->toString().c_str());
				#if 1
				if( e->ts > 1841717600000 ) {
					debug(30, "Found Future in record: %s", e->toString().c_str());
				}
				#endif
				if (e->id_orig_h.s_addr == 0 && e->id_resp_h.s_addr == 0){
					debug(55, "Warning: trouble parsing dataFlow, may be IPv6: '%s'\n", e->toString().c_str());
					numDropIPv6 += 1;
					delete e;
				}
				else {
					results->push_back(e);
					number += 2;
				}
			}
			flowNum -= 1;
			//END FLOWS
		}
	//END FLOWSETS
	}
	if(position != size && (size - position) > 20) {
		debug(10, "WARNING: Encountered a record (most recent id = %u) that was %i bytes too large. Attempting to rectify.\n", id, size - position);
		//Recover for this by trying to read the next x bytes
		if(versionHandler((uint8_t *)buf+position) == 9) {//If the next bytes are the beginning of another record
			debug(15, "%i bytes form a new record. Trying it\n", size - position);
			number += parseBuf(buf+position, size - position, f, results);
		}
		else {
			debug(15, "%i bytes do not form a new record.\n", size - position);
		}
	}
	else if(position != size) {
		debug(10, "warning: Dropped %i bytes at the end of the record (most recent id = %u). Too small to try to recover from.\n", size - position, id);
	}
	return number;
}

KeyValuePair *NetV9::createPair(uint8_t index, std::list<logEntry*> *results, uint8_t source) {
	debug(80, "current size of results: %lu, index = %d\n", results->size(), index);
	NetV9_Entry e  = *results->front();
	if( index % 2 != 0 ) {
		delete results->front();
		results->pop_front();
	}

	//create the key using index as a marker of whether the key should be reversed
	//the first key will have index of 0 so false and next will be one so true (repeat as needed)
	IP_Key *key = new IP_Key(&(e.id_orig_h), e.ts , e.id_orig_p, 
			&(e.id_resp_h), e.id_resp_p, index);
	NetV9_Value *value = new NetV9_Value(source, e.proto, e.duration,
			e.bytes, e.tcp_flags, e.pkts);
	KeyValuePair *pair = new KeyValuePair(*key, *value);
	return pair;
}

//------------------------------
//function which uses diventiStream to read a line from the conn.log

//FUNCTIONALITY CURRENTLY DISABLED as it doesn't work with the current
//	grab one record protocol
int NetV9::getRawData(char * /*buf*/, DiventiStream */*stream*/) {
	
	return 0;
}

unsigned int NetV9::getSyslogData(SyslogHandler *slh, char *buf, logFormat **/*fp*/) {
	int size = 0;
	while(true) {
		size = slh->getNextPacket(buf, sysMaxSize);
		if (size > 0) {
			debug(70, "Getting record, size recieved: %d\n", size);
			uint16_t version = versionHandler((uint8_t *)buf);
			if(version != 9) {
				debug(1, "Unexpected netflow version %u ... discarding record\n", version);
				numDropVer += 1;
				continue;
			}
			// size = slh->getNextBytes(buf+4, length, fp) + 4;
			
			// buf = sysPacket + sysOffset;
			//The amount of data ingested over the course of the entire packet = size of packet
			//Then we found what we expected
			return size;
		}
		return 0;
	}
}

Key *NetV9::createKey(DBT *dbt) {
	IP_Key *key = new IP_Key(dbt);
	return key;
}

Value *NetV9::createValue(DBT *dbt) {
	NetV9_Value *value = new NetV9_Value(dbt);
	return value;
}

std::string NetV9::getHeader() {
	return "ts           	orig_ip   	orig_port   	resp_ip     	resp_port    	proto   duration   bytes  	tcp_flags  	packets";
}

/*
 * Returns the first header of the file. However, since NetV9 file reading is not implemented
 * This function is also not implemented and just returns an empty string
 */
std::string NetV9::getKey(std::string /*fileName*/){
	return "";
}

//Temporary setup because I know what 256 should be... should be removed or changed 
logFormat *NetV9::createFormat(std::string /*fields*/) {
	//Matches the current data
	#if 0
	NetV9_Format *form = new NetV9_Format();
	form->fieldHandler[0] = BytesHandler;
	form->locations[0] = 0;
	form->fieldHandler[1] = PktsHandler;
	form->locations[1] = 8;
	form->fieldHandler[2] = ProtoHandler;
	form->locations[2] = 16;
	form->fieldHandler[3] = FlagsHandler;
	form->locations[3] = 17;
	form->fieldHandler[4] = OPortHandler;
	form->locations[4] = 18;
	form->fieldHandler[5] = OIPHandler;
	form->locations[5] = 20;
	form->fieldHandler[6] = RPortHandler;
	form->locations[6] = 28;
	form->fieldHandler[7] = RIPHandler;
	form->locations[7] = 30;
	form->fieldHandler[8] = TimeHandler;
	form->locations[8] = 48;
	form->fieldHandler[9] = DurHandler;
	form->locations[9] = 56;
	form->lastToken = 10;
	form->totalSize = 64;
	templates[256] = form;
	debug(60, "Fields Parsed lastToken:%d\n%s\n", form->lastToken, form->toString().c_str());
	#endif
	//matches the current verification script
	#if 1
	NetV9_Format *form = new NetV9_Format();
	form->fieldHandler[0] = BytesHandler;
	form->locations[0] = 0;
	form->fieldHandler[1] = PktsHandler;
	form->locations[1] = 8;
	form->fieldHandler[2] = ProtoHandler;
	form->locations[2] = 16;
	form->fieldHandler[3] = OPortHandler;
	form->locations[3] = 17;
	form->fieldHandler[4] = OIPHandler;
	form->locations[4] = 19;
	form->fieldHandler[5] = RPortHandler;
	form->locations[5] = 27;
	form->fieldHandler[6] = RIPHandler;
	form->locations[6] = 29;
	form->fieldHandler[7] = TimeHandler;
	form->locations[7] = 45;
	form->fieldHandler[8] = DurHandler;
	form->locations[8] = 53;
	form->lastToken = 9;
	form->totalSize = 61;
	templates[256] = form;
	debug(60, "Fields Parsed lastToken:%d\n%s\n", form->lastToken, form->toString().c_str());
	#endif
	return nullptr;
}
