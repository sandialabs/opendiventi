#ifndef DEBUG_INCLUDED_DIVENTI
#define DEBUG_INCLUDED_DIVENTI
#include "diventi.h"
#ifdef DEBUG
#define debug(lvl, fmt, ...)  if (debug_level >= lvl) fprintf(stderr, "%s:%d: " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define debug(lvl, fmt, ...)    /* Don't do anything in release builds */
#endif

extern int debug_level;

#endif