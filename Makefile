#
# Copyright 2019 National Technology & Engineering Solutions of
# Sandia, LLC (NTESS). Under the terms of Contract DE-NA0003525
# with NTESS, the U.S. Government retains certain rights in this
# software.
#

SHELL := /bin/bash

#
#  Provide a pointer to the tokudb ft-index libraries
TOKUFTLIB = ../ft-index/prefix
BOOSTPREFIX = ../boostPrefix
BOOSTLIB = $(BOOSTPREFIX)/lib
BOOSTINCLUDE = $(BOOSTPREFIX)/include

#  Uncomment second item to remove debug printing.
DEBUGF=-DDEBUG
#DEBUGF=
#  Uncomment second item to remove benchmark timing.
BENCHMARKF=-DBENCHMARK
#BENCHMARKF=
VPATH=../src
SRCS = $(wildcard ../src/*.cpp)
#OBJECTS = Key.o Value.o KeyValuePair.o TokuHandler.o InsertThread.o FileHandler.o Watcher.o Control.o Server.o Client.o QueryHandler.o DiventiProcessed.o DiventiStream.o Parse.o SyslogHandler.o

# CORE_OBJ = IP_Key.o Basic_Key.o Bro_Value.o Mon_Value.o Net_Value.o NetV9_Value.o Basic_Value.o KeyValuePair.o MurmurHash3.o TokuHandler.o DiventiProcessed.o DiventiStream.o
CORE_OBJ = IP_Key.o Basic_Key.o Bro_Value.o Mon_Value.o Net_Value.o NetV9_Value.o Basic_Value.o KeyValuePair.o TokuHandler.o DiventiProcessed.o DiventiStream.o
SERVER_OBJ = Bro_Parse.o Mon_Parse.o Net_Parse.o Basic_Parse.o NetV9_Parse.o InsertThread.o FileHandler.o Watcher.o Control.o Server.o SyslogHandler.o QuerySession.o bro_functions.o Mon_functions.o netAscii_functions.o NetV5_functions.o Basic_functions.o NetV9_functions.o

OBJECTS = $(CORE_OBJ) $(SERVER_OBJ)

TARGETS = $(patsubst %.c,%,$(SRCS))

TESTSRC = $(wildcard ../src/test_*.cpp) 
TESTS = $(patsubst ../src/%.cpp, %, $(TESTSRC))

CPPFLAGS = -isystem$(TOKUFTLIB)/include -D_GNU_SOURCE -DTOKUDB $(DEBUGF) $(BENCHMARKF) -std=c++0x
CFLAGS = -g -Wall -Wextra -Werror
ifeq ($(USE_STATIC_LIBS),1)
LIBTOKUDB = tokufractaltree_static
LIBTOKUPORTABILITY = tokuportability_static
else
LIBTOKUDB = tokufractaltree
LIBTOKUPORTABILITY = tokuportability
endif
LDFLAGS = -L$(TOKUFTLIB)/lib -l$(LIBTOKUDB) -l$(LIBTOKUPORTABILITY) -lpthread -lz -ldl -L$(BOOSTLIB) -lboost_filesystem -lboost_system -lboost_thread -lboost_program_options -lboost_date_time -lboost_iostreams -lboost_serialization -Wl,-rpath,$(TOKUFTLIB)/lib,-rpath,$(BOOSTLIB)
print-%: ; @echo $*=$($*)
# default local: $(OBJECTS) diventiQuery diventiServer testWrites
default local: $(OBJECTS) diventiServer testWrites

.PHONY: install
install:
	. initialSetup.sh

.PHONY: test
tests: $(TESTS)
	. ../tests/runTests.sh

test_%: $(OBJECTS) test_%.cpp diventi.cpp
	$(CXX)  ../src/test_$*.cpp ../src/diventi.cpp $(OBJECTS) $(CPPFLAGS) $(CFLAGS) -o $@ $(LDFLAGS) -isystem $(BOOSTINCLUDE)


# ClientsideCli: diventiQuery
#	cp diventiQuery ClientsideCli

ServersideCli: diventiServer
	cp diventiServer ServersideCli

#diventiQuery: $(CORE_OBJ) $(CLIENT_OBJ) ClientsideCli.cpp diventi.cpp
#	$(CXX) ../src/ClientsideCli.cpp ../src/diventi.cpp $(CORE_OBJ) $(CLIENT_OBJ) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o diventiQuery -isystem $(BOOSTINCLUDE)

diventiServer: $(CORE_OBJ) $(SERVER_OBJ) ServersideCli.cpp diventi.cpp
	$(CXX) ../src/ServersideCli.cpp ../src/diventi.cpp $(CORE_OBJ) $(SERVER_OBJ) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o diventiServer -isystem $(BOOSTINCLUDE)

testWrites: $(CORE_OBJ) Control.o testWrites.cpp diventi.cpp
	$(CXX) ../src/testWrites.cpp ../src/diventi.cpp $(CORE_OBJ) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o testWrites -isystem $(BOOSTINCLUDE)


IP_Key.o: IP_Key.cpp IP_Key.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/IP_Key.cpp -o IP_Key.o

Basic_Key.o: Basic_Key.cpp Basic_Key.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/Basic_Key.cpp -o Basic_Key.o

Bro_Value.o: Bro_Value.cpp Bro_Value.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/Bro_Value.cpp -o Bro_Value.o

Mon_Value.o: Mon_Value.cpp Mon_Value.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/Mon_Value.cpp -o Mon_Value.o

Net_Value.o: Net_Value.cpp Net_Value.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/Net_Value.cpp -o Net_Value.o

NetV9_Value.o: NetV9_Value.cpp NetV9_Value.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/NetV9_Value.cpp -o NetV9_Value.o

Basic_Value.o: Basic_Value.cpp Basic_Value.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/Basic_Value.cpp -o Basic_Value.o

KeyValuePair.o: KeyValuePair.cpp KeyValuePair.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/KeyValuePair.cpp -o KeyValuePair.o

# MurmurHash3.o: MurmurHash3.cpp MurmurHash3.h
# 	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/MurmurHash3.cpp -o MurmurHash3.o

Bro_Parse.o: Bro_Parse.cpp Bro_Parse.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/Bro_Parse.cpp -o Bro_Parse.o -isystem $(BOOSTINCLUDE)

Mon_Parse.o: Mon_Parse.cpp Mon_Parse.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/Mon_Parse.cpp -o Mon_Parse.o -isystem $(BOOSTINCLUDE)

Net_Parse.o: Net_Parse.cpp Net_Parse.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/Net_Parse.cpp -o Net_Parse.o -isystem $(BOOSTINCLUDE)

Basic_Parse.o: Basic_Parse.cpp Basic_Parse.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/Basic_Parse.cpp -o Basic_Parse.o -isystem $(BOOSTINCLUDE)

NetV9_Parse.o: NetV9_Parse.cpp NetV9_Parse.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/NetV9_Parse.cpp -o NetV9_Parse.o -isystem $(BOOSTINCLUDE)

InsertThread.o: InsertThread.cpp InsertThread.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/InsertThread.cpp -o InsertThread.o -isystem $(BOOSTINCLUDE)

TokuHandler.o: TokuHandler.cpp TokuHandler.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/TokuHandler.cpp -o TokuHandler.o

FormatParser.o: FormatParser.cpp FormatParser.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/FormatParser.cpp -o FormatParser.o -isystem $(BOOSTINCLUDE)

FileHandler.o: FileHandler.cpp FileHandler.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/FileHandler.cpp -o FileHandler.o -isystem $(BOOSTINCLUDE)

Watcher.o: Watcher.cpp Watcher.h FileHandler.o
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/Watcher.cpp -o Watcher.o -isystem $(BOOSTINCLUDE)

Control.o: Control.cpp Control.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/Control.cpp -o Control.o -isystem $(BOOSTINCLUDE)

Server.o: Server.cpp Server.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/Server.cpp -o Server.o -isystem $(BOOSTINCLUDE)

Client.o: Client.cpp Client.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/Client.cpp -o Client.o -isystem $(BOOSTINCLUDE)

QuerySession.o: QuerySession.cpp QuerySession.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/QuerySession.cpp -o QuerySession.o -isystem $(BOOSTINCLUDE)

DiventiStream.o: DiventiStream.cpp DiventiStream.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/DiventiStream.cpp -o DiventiStream.o -isystem $(BOOSTINCLUDE)

DiventiProcessed.o: DiventiProcessed.cpp DiventiProcessed.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/DiventiProcessed.cpp -o DiventiProcessed.o -isystem $(BOOSTINCLUDE)

SyslogHandler.o: SyslogHandler.cpp SyslogHandler.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/SyslogHandler.cpp -o SyslogHandler.o -isystem $(BOOSTINCLUDE)

bro_functions.o: bro_functions.cpp bro_functions.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/bro_functions.cpp -o bro_functions.o -isystem $(BOOSTINCLUDE)

Mon_functions.o: Mon_functions.cpp Mon_functions.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/Mon_functions.cpp -o Mon_functions.o -isystem $(BOOSTINCLUDE)

netAscii_functions.o: netAscii_functions.cpp netAscii_functions.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/netAscii_functions.cpp -o netAscii_functions.o -isystem $(BOOSTINCLUDE)

NetV5_functions.o: NetV5_functions.cpp NetV5_functions.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/NetV5_functions.cpp -o NetV5_functions.o -isystem $(BOOSTINCLUDE)

Basic_functions.o: Basic_functions.cpp Basic_functions.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/Basic_functions.cpp -o Basic_functions.o -isystem $(BOOSTINCLUDE)

NetV9_functions.o: NetV9_functions.cpp NetV9_functions.h
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c  ../src/NetV9_functions.cpp -o NetV9_functions.o -isystem $(BOOSTINCLUDE)

# %: %.c
# 	$(CC) $(CPPFLAGS) $(CFLAGS) $^  -o ../build/$@ $(LDFLAGS)

# %: %.cpp diventi.cpp
# 	$(CXX) $^ $(CPPFLAGS) $(CFLAGS) -o ../build/$@ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f *.o rm test_*

.PHONY: superclean
superclean:
	rm -f *.o rm test_* diventiQuery diventiServer testWrites
