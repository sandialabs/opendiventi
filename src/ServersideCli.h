#ifndef SERVERSIDECLI_INCLUDED_DIVENTI
#define SERVERSIDECLI_INCLUDED_DIVENTI

struct StartOptions;
typedef struct startOptions startOptions;

class ServersideCli {
public:
	startOptions* parse(int argc, const char** argv);
private:

};


#endif