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

After doing the above, install Diventi by running `make install`. It will prompt you to make necessary configurations if needed.

# Usage
Most server options are configured using the config.ini file. This file has detailed instructions on how to tell Diventi what data sources to use.

Once you've installed you can run diventiServer -h from /build to get more instructions for configuring the server via the command line.



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
diventi records the following fields in the database:
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

# Implementing a New Event Format
Data that can be expressed as a key and a value can be ingested by diventi.  
To create a format simply write concrete classes to fill in the required fields created by the abstract classes found in diventi.h and then fill in the if statements for the name of the format at the required locations. Places in the general purpose files where changes are necessary are marked by the comment `NEWFORMAT`.

# Ingestion Sources

Diventi supports event ingestion from two possible sources: files and the syslog port. File ingestion is good for older data or data from other networks. Syslog is for data received over UDP and is ideal for indexing live environments.

# Unit Tests
In alphabetic order. Their file names are prefixed with "test_". These can be compiled and run with `make tests`.

| Unit Test | Purpose |
| :-------: | ------- |
|cont_file  | Tests actively monitoring a directory and re-queuing files which were previously finished being ingested but have been updated. |
| edge_case_query | Tests a query edge case. |
| formats | Tests the various output formats |
| many_small_insert | Tests the ingestion of multiple files. |
| multithread_insert | Tests multi-threaded ingestion of a single file. |
| netAscii | tests ability to ingest netflow ascii logs |
| netBinary | tests ability to ingest netflow binary logs |
| net_parsing | Tests the parsing of netflow records |
| parsing | Tests the flexibility of parsing bro logs in various formats. |
| range_query | Tests a range query on the database. |
| range_server | Tests a range query submitted over the network to the server. |
| server | Tests setting up the server. |
| server_dropped | Tests server response to dropping a connection to the server on the client side. |
| single_query | Tests a single query to the database. |
| single_server | Tests a single query submitted over the network to the server. |
| small_insert | Tests ingestion of a single file. |
| vacant_query | Tests database response to a query which will return no results. |
| vacant_server | Tests server response to a query which will return no results. |
| watcher | Tests watching a directory for the creation of new files. |

Additionally, testWrites provides a benchmark for raw database ingestion rate, not including parsing files.

# Query Scripting
Queries have a standardized HTTP interface, so it is possible for commonly made queries to be scripted.

Queries should be made to DIVENTI_IP:41311/query with an HTTP GET request.

Arguments are:

| Argument| Effect|
| :------| :----|
| **ip** | The singular ip or start ip to query for. |
| **range** | If this argument is specified, queries for ip addresses between **ip** and **range** |
| **type**	| If this argument is specified than use either **json** or **bin**(binary) formatting for the response. Defaults to **none**.|
| **startTime** | The earliest time to look for. This should be in seconds from epoch. If not specified, defaults to 0. |
| **endTime** | The latest time to look for. This should be in seconds from epoch. If not specified, defaults to the end of time (more or less). |

Note that **ip** must be specified in all queries.

Example query: DIVENTI_IP:41311/query?ip=192.168.1.1&range=192.168.2.1  
This will query for all activity for ips between 192.168.1.1 and 192.168.2.1, inclusive.  

Json query: DIVENTI_IP:41311/query?ip=100.168.1.1&range=192.168.2.1&type=json  
This will query for all activity for ips between 100.168.1.1 and 192.168.2.1, inclusive.  
The results will be returned as a json string.  

Binary query: DIVENTI_IP:41311/query?ip=100.168.1.1&range=192.168.2.1&type=bin&startTime=X  
This will query for all activity from startTime X for ips between 100.168.1.1 and 192.168.1.1, inclusive.  
The results are returned as binary in a string.  
See bin_functions.py for functions that can extract data from the string.  

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
