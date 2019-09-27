#!/bin/bash

function add_path()
{
	# $1 path variable
	# $2 path to add
	if [ -d "$2" ] && [[ ":$1:" != *":$2:"* ]]; then
		echo "$1:$2"
	else
		echo "$1"
	fi
}

A=${BASH_SOURCE[0]}
SCRIPT=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
SCRIPTPATH=$(dirname $SCRIPT)

TOKUDB_DIR=/ft-index

export CFLAGS="$CFLAGS -I$TOKUDB_DIR/prefix/include"
export CXXFLAGS="$CXXFCLAGS -I$TOKUDB_DIR/prefix/include"
export CGO_LDFLAGS="$LDFLAGS -L$TOKUDB_DIR/build/portability -L$TOKUDB_DIR/build/src -L$TOKUDB_DIR/lib -ltokuportability -ltokufractaltree"
export LD_LIBRARY_PATH=$(add_path $LD_LIBRARY_PATH $TOKUDB_DIR/lib:$TOKUDB_DIR/build:$TOKUDB_DIR/build/src:$TOKUDB_DIR/build/portability)
export DYLD_LIBRARY_PATH=$(add_path $DYLD_LIBRARY_PATH $TOKUDB_DIR/lib)

#save the working directory
cwd=$(pwd)
echo $cwd
#clone ft index and dependencies
if [ ! -d "ft-index" ]; then
	git clone "git://github.com/Tokutek/ft-index.git" "ft-index"
fi
cd ft-index

if [ ! -d "third_party/jemalloc" ]; then
	git clone "git://github.com/Tokutek/jemalloc.git" "third_party/jemalloc" 
fi


# Check for dependencies
dependencies="zlib1g-dev libbz2-dev cmake"
unmet=""
for dep in $dependencies; do
	if [[ $(dpkg -s $dep 2>/dev/null) != *"Status: install ok installed"* ]]; then
		unmet+="$dep "
	fi
done
if [ ! -z "$unmet" ]; then
	echo -e "\nError initializing: please install the following dependencies"
	for dep in $unmet; do
		echo -e "\t$dep"
	done
	cd $cwd
	return
fi

#if ft-index is not already built, then build it
if [ ! -d "build" ]; then
	mkdir build
	cd build
	#Old way CC=gcc47 CXX=g++47 cmake
	CC=gcc CXX=g++ cmake -D CMAKE_BUILD_TYPE=Release -D BUILD_TESTING=ON -D USE_VALGRIND=OFF -D CMAKE_INSTALL_PREFIX=../prefix/ .. 
	cmake --build . --target install
fi

cd $cwd

# If boost is not present or built, then fetch/build it
if [ ! -d "boostPrefix" ]; then
	wget https://dl.bintray.com/boostorg/release/1.66.0/source/boost_1_66_0.tar.gz --no-check-certificate
	tar -xzf boost_1_66_0.tar.gz
	cd boost_1_66_0
	mkdir ../boostPrefix
	./bootstrap.sh --prefix=../boostPrefix --with-libraries=filesystem,system,thread,chrono,date_time,program_options,iostreams,serialization
	./b2 install
fi
cd boostPrefix
BOOST_PREFIX=$(pwd)
export PATH=$(add_path $PATH $BOOST_PREFIX/bin)
echo $PATH

cd $cwd

thp_cmds=""
if [ -f "/sys/kernel/mm/transparent_hugepage/enabled" ] && [ "$(cat /sys/kernel/mm/transparent_hugepage/enabled)" != "always madvise [never]" ]; then
	thp_cmds+=$'\techo never > /sys/kernel/mm/transparent_hugepage/enabled\n'
fi
if [ -f "/sys/kernel/mm/transparent_hugepage/defrag" ] && [ "$(cat /sys/kernel/mm/transparent_hugepage/defrag)" != "always madvise [never]" ] && [ "$(cat /sys/kernel/mm/transparent_hugepage/defrag)" != "always defer defer+madvise madvise [never]" ]; then
	thp_cmds+=$'\techo never > /sys/kernel/mm/transparent_hugepage/defrag'
fi
if [ ! -z "$thp_cmds" ]; then
	echo -e "\nError initializing: please disable transparent hugepages"
	echo "Run the following commands as root to do so: "
	echo "$thp_cmds"
	exit
fi

if [ ! -d "build" ]; then
	mkdir build
fi
cp Makefile build/Makefile
cd build
cp ../config.ini ./

make clean
make
echo $pwd
make tests

cd $cwd


if [[ $(cat /proc/sys/fs/inotify/max_user_watches) -lt 500000 ]];then
	echo "You may wish to use the following command to increase the number of files Diventi can monitor:"
	echo "sysctl fs.inotify.max_user_watches=500000"
	echo "Some of the tests may have failed if this value is too low."
fi
