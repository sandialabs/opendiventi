#ifndef BASIC_PARSE_BLOCK
#define BASIC_PARSE_BLOCK


#include "diventi.h"
#include "Basic_Value.h"
#include <stdint.h>
#include <string>
#include <netinet/in.h>




class BasicFormat: public logFormat {
  enum logField {
    ALTITUDE, OBSERVATION,
    UNUSED, UNKNOWN
  };

  static int const MAX_FIELDS=2;

 public:
	BasicFormat(std::string fields);
	BasicFormat();


        logField type[MAX_FIELDS];
	int lastToken; // The last token we need to process.
	
	handler_t fieldHandler[MAX_FIELDS];

	std::string toString() const;
	~BasicFormat(){}

	bool operator==(const logFormat& other);
	inline bool operator!=(const logFormat& other){ return !(*this == other); }
	BasicFormat *operator=(const logFormat& other);
	void parse(std::string fields);

 private:
        static const std::string fieldStr[4];

};

// A parsed entry
class BasicEntry: public logEntry{
public:
	uint32_t altitude;

	char observation[40];

	// logEntry(char *buf, int size, logFormat *fp);
	BasicEntry();
	~BasicEntry();
	bool operator==( logEntry& other);
	inline bool operator!=( logEntry& other){ return !(*this == other); }
	BasicEntry *operator=(const logEntry& other);
	// void parse(std::string line, logFormat *fp);
	//void parseBuf(char * buf, int size, logFormat *fp);
	std::string toString();
};

#endif
