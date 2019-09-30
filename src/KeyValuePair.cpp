#include "KeyValuePair.h"

#include "diventi.h"

KeyValuePair::KeyValuePair(Key& k, Value& v) : key(&k), value(&v){}

KeyValuePair::~KeyValuePair() {}

Key *KeyValuePair::getKey() {
	return key;
}

Value *KeyValuePair::getValue() {
	return value;
}

bool KeyValuePair::operator==(const KeyValuePair& other) {
	return *key == *other.key && *value == *other.value;
}

bool KeyValuePair::operator!=(const KeyValuePair& other) {
	return !(*this == other);
}
