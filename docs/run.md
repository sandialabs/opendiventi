# Usage
Most server options are configured using the `config.ini` file. This file has detailed instructions on how to tell Diventi what data sources to use.

### Data Sources
These are configured in the `config.ini` file and tell Diventi how to collect data to ingest and what format that data takes.

| Argument| Effect|
| :------| :----|
| **[sourcex]** | source number given as x where x is in the range [1,255] |
| **logFormat** | bro, mon, NetV5, netAscii, or NetV9. Informs Diventi of the type of data to be recieved from this source. |
| **tag** | name of the source that will be printed in query responses. |
| **inputDir** | directory which contains the files this source will ingest. |
| **fileNameFormat** | regex which files to be ingested by this source much match. |
| **syslogPort** | Port to recieve syslogs on. |
| **syslogArgs** | Argument which defines the fields for a format like bro, when recieving over syslog. |

Sources are constructed like this:

```
[sourcex]
logFormat	= (string)
tag		= (string)
# add the following if recieving data from files
inputDir	= (string)
fileNameFormat= (string)
# add the following if recieving data over syslog
syslogPort	= (int)
syslogArgs	= (string)
```

### Server Options

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

# Formats
* Bro-conn
* Netflow v5 ascii
* Netflow v5 binary
* Netflow v9
* Mon
* Any other format the developer implements

## Bro-conn
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

## Netflow v5
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

## Netflow v9
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

## Mon
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

# Ingestion Sources
Diventi supports event ingestion from two possible sources: files and the syslog port. File ingestion is good for older data or data from other networks. Syslog is for data received over UDP and is ideal for indexing live environments. See `config.ini` and the `Data Sources` section above for how to set up data sources.