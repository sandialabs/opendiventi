#include "diventi.h"

// const int NUMBER = 5;
startOptions OPTIONS;
int debug_level = 0;

// AbstractLog *functions; //declare global instance of function class (determines format specific functions)
comparer keyCompare;  //global function pointer for comparing keys 

Key::~Key() {}
Value::~Value() {}
// KeyValuePair::~KeyValuePair() {}
AbstractLog::~AbstractLog() {}
logFormat::~logFormat() {}
logEntry::~logEntry() {}