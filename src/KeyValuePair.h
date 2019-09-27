#ifndef KEYVALUEPAIR_INCLUDED_DIVENTI
#define KEYVALUEPAIR_INCLUDED_DIVENTI

#include "diventi.h"

class KeyValuePair {
public:
	KeyValuePair(Key& k, Value& v);
	~KeyValuePair();
	Key *getKey();
	Value *getValue();
	bool operator==(const KeyValuePair& other);
	bool operator!=(const KeyValuePair& other);
private:
	Key *key;
	Value *value;
};
#endif
