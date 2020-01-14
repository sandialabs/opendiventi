### Copyright 2019 National Technology & Engineering Solutions of
### Sandia, LLC (NTESS). Under the terms of Contract DE-NA0003525
### with NTESS, the U.S. Government retains certain rights in this
### software.


# Introduction

Access to network traffic records is an integral part of recognizing and addressing network security breaches. Even with the increasing sophistication of network attacks, basic network events such as connections between two IP addresses play an important role in any network defense. Given the duration of current attacks, long-term data archival is critical but typically very little of the data is ever accessed. Previous work has provided tools and identified the need to trace connections. However, traditional databases raise performance concerns as they are optimized for querying rather than ingestion. The study of write-optimized data structures (WODS) is a new and growing field that provides a novel approach to traditional storage structures (e.g., B-trees). WODS trade minor degradations in query performance for significant gains in the ability to quickly insert more data elements, typically on the order of 10 to 100 times more inserts per second. These efficient, out-of-memory data structures can play a critical role in enabling robust, long-term tracking of network events. Diventi uses a write-optimized B-tree known as a B^ɛ tree to track all IP address connections in a network traffic stream.

Diventi is a write optimized database system for recording Network Events. Currently it is only available for use on Unix systems.


Development began at Sandia National Labs during the summer of 2016 in Livermore.



# Installation
In order for installation to complete successfully, you will need the following dependencies installed.
* zlib1g-dev 
* libbz2-dev
* cmake

Additionally, transparent huge pages should be disabled. These are enabled by default on many systems, and some of our dependencies require that they be disabled. You can disable them using the following commands:
```
$ sudo su
$ echo never > /sys/kernel/mm/transparent_hugepage/enabled
$ echo never > /sys/kernel/mm/transparent_hugepage/defrag
$ exit
```

Additionally if you'd like to make these changes persist across system restarts then add the following to your `/etc/rc.local` file:
```
if test -f /sys/kernel/mm/transparent_hugepage/enabled; then
   echo never > /sys/kernel/mm/transparent_hugepage/enabled
fi
if test -f /sys/kernel/mm/transparent_hugepage/defrag; then
   echo never > /sys/kernel/mm/transparent_hugepage/defrag
fi
```

After doing the above, install Diventi by running `make install`. It will prompt you to make necessary configurations if needed.

# Usage
Most server options are configured using the `config.ini` file. This file has detailed instructions on how to tell Diventi what data sources to use.

In addition to data sources the following general configuration options are available:

| Argument| Effect|
| :------| :----|
| **dbDir** | The directory in which to store the database. Need not exist. |
| **numIThreads** | The number of insertion threads. |
| **numQThreads**	| The number of threads to handle queries. |
| **watchIDir** | If true, insertion directories are watched for additional or changing directories. |
| **queryPort** | Which port to recieve HTTP queries on. Default is 41311. |
| **tokuPagesize** | The size of the buffer at each toku node. |
| **tokuFanout** | The maximum number of children each toku node can have. |
| **tokuCompression** | The level of data compression options are `no`, `fast`, `default`, and `small`. |
| **tokuCleanerPeriod** | The time in seconds between each run of the toku cleaner thread |
| **tokuCleanerIterations** | The number of buffers cleaned on each run of the toku cleaner thread |
| **threadBase** | The number of insertions to wait before adding the second insertion thread. |
| **threadExp** | The amount to scale threadbase by to add the next thread. Must be greater than `1`. `1.3` would be a 130% increase. |
| **cleanDelay** | The number of insertions to wait before activating the cleaners. |

Once you've installed you can run diventiServer -h from /build to for instructions on how to implement some of these options via the command line.

# Queries
Queries have a standardized HTTP interface, so it is possible for commonly made queries to be scripted.

Queries should be made to DIVENTI_IP:41311/query with an HTTP GET request. Or if the server has a different query port specified that should be used in place of 41311.

Arguments are:

| Argument| Effect|
| :------| :----|
| **ip** | The singular ip or start ip to query for. |
| **range** | If this argument is specified, queries for ip addresses between **ip** and **range** |
| **type**	| If this argument is specified than use either **json** or **bin**(binary) formatting for the response. Defaults to **none**.|
| **logs**  | The maximum number of logs to return in an answer. Default = 1000 |
| **startTime** | The earliest time to look for. This should be in seconds from epoch. If not specified, defaults to 0. |
| **endTime** | The latest time to look for. This should be in seconds from epoch. If not specified, defaults to the end of time (more or less). |
| **cursor** | The dbt to start searching from. Users should not enter this option. It will be generated automatically by Diventi. |

Note that **ip** must be specified in all queries.

Example query: DIVENTI_IP:41311/query?ip=192.168.1.1&range=192.168.2.1  
This will query for all activity for ips between 192.168.1.1 and 192.168.2.1, inclusive.  

Json query: DIVENTI_IP:41311/query?ip=192.168.1.1&range=192.168.2.1&type=json  
This will query for all activity for ips between 192.168.1.1 and 192.168.2.1, inclusive.  
The results will be returned as a json string.  

Binary query: DIVENTI_IP:41311/query?ip=100.168.1.1&range=192.168.2.1&type=bin&startTime=X  
This will query for all activity from startTime X for ips between 100.168.1.1 and 192.168.1.1, inclusive.  
The results are returned as binary in a string.  
See bin_functions.py for functions that can extract data from the string.

### Get Sources
Or you can send a query with just the argument `sources` to get a list of the current sources Diventi is using.  
ex: DIVENTI_IP:41311/query?sources
# Formats
* Bro-conn
* Netflow v5 ascii
* Netflow v5 binary
* Netflow v9
* Mon
* Any other format the developer implements

# Bro-conn
Diventi can parse Bro logs which contain any combination of standard Bro conn log fields (a list can be found at https://www.bro.org/sphinx-git/scripts/base/protocols/conn/main.bro.html#type-Conn::Info).  
However, it only records the following fields in the database:
* ts
* id.orig_h
* id.orig_p
* id.resp_h
* id.resp_p
* proto
* duration
* orig_bytes
* resp_bytes
* conn_state
* orig_pkts
* resp_pkts

Non-present fields are denoted by "-" or -1, for strings and numerical values, respectively, in the queries.  
The database is indexed by IP, port, and timestamp. Currently Diventi supports lookup by timestamp and IP from either side (the user does not specify orig/resp).

# Netflow v5
Diventi can parse both netflow binary and ascii. The ascii parsing is very similar to bro-conn parsing. Binary format parses the netflow headers and data fields to get the relevant data.  
Information about netflow can be found at https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html  
Diventi records the following fields in the database:
* ts (requires SysUptime, unix_secs, First, and Last)
* srcaddr
* srcport
* dstaddr
* dstport
* prot
* duration (requires First and Last)
* dOctets
* tcp_flags
* dPkts

Queries are the same as they are for bro-conn

# Netflow v9
Diventi can currently only ingest Netflow v9 that is transmitted over syslog. Diventi holds records on the following fields if they are present within a template.
* bytes(1)
* packets(2)
* protocol(4)
* tcp_flags(6)
* src_port(7)
* src_ip(8)
* dst_port(11)
* dst_ip(12)
* start_m(152)
* end_m(153)

Note that the last two are options which are addons to the standard Netflow v9 format options. These are the start time of the conneciton and the end time in milliseconds. Slight modifications to the code base would be needed to track time using different options.

# Mon
Diventi ingests udp, icmp, and tcp Mon logs. Tracking the following fields
* timestamp
* srcaddr
* srcport
* dstaddr
* dstport
* protocol
* duration
* origin_bytes
* resp_bytes
* tcp_flags

# Implementing a New Event Format
Data that can be expressed as a key and a value can be ingested by diventi.  
To create a format simply write concrete classes to fill in the required fields created by the abstract classes found in diventi.h and then fill in the if statements for the name of the format at the required locations. Places in the general purpose files where changes are necessary are marked by the comment `NEWFORMAT`.

# Ingestion Sources
Diventi supports event ingestion from two possible sources: files and the syslog port. File ingestion is good for older data or data from other networks. Syslog is for data received over UDP and is ideal for indexing live environments. See `config.ini` for how to set up data sources.

# Maintainers
Evan West: contact at ewest@sandia.gov  
Thomas Kroeger: contact at tmkroeg@sandia.gov  

# Contributers
Justin Raizes  
Cindy Phillips  
Michael Bender  
Rob Johnson  
Bridger Hahn  
Nolan Donoghue  
Helen Xu  
David Zage  
Matthew Gray
