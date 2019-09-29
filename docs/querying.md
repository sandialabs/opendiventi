# Queries
Queries have a standardized HTTP interface, so it is possible for commonly made queries to be scripted.

Queries should be made to DIVENTI_IP:41311/query with an HTTP GET request. Or if the server has a different query port specified that should be used in place of 41311.

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

# Querying Directory
This directory contains a few examples of querying scripts and a general purpose diventi querier.

## QueryClient.py
This script is used for general purpose point and range queries to the Diventi server.

### USAGE
minimum needed

./QueryClient.py diventiIP(unless defined elsewhere) queryIP

#### OPTIONS
* -r RANGE 	the range of IPs between queryIP and range (inclusive) are queried upon
* -s START 	Defines the first timestamp, all timestamps between start and end (inclusive) are queried upon
* -e END 		Defines the last timestamp, all timestamps between start and end (inclusive) are queried upon
* -f FORM		Defines the format of the returned data
* -p 			Return performance data about the query

#### Format Options
* none (the default): returns ascii
* json: returns a json string
* bin: returns binary data
* verbose: returns ascii with expanded fields (human readable time for example)

#### Examples with diventiIP: 0.0.0.0
Query a specific ip address: 225.100.90.10
`./QueryClient 0.0.0.0 255.100.90.10`

Query a range of ips starting at 10.50.90.100 and ending with 100.0.0.0
`./QueryClient 0.0.0.0 10.50.90.100 -r 100.0.0.0`

Query for all records of ip 10.0.0.0 after timestamp 123456789
`./QueryClient 0.0.0.0 10.0.0.0 -s 123456789`

Query for all records of ip 10.0.0.0 before timestamp 987654321
`./QueryClient 0.0.0.0 10.0.0.0 -e 987654321`

Query for all records of ip 10.0.0.0 after timestamp 123456789 and before timestamp 987654321
`./QueryClient 0.0.0.0 10.0.0.0 -s 123456789 -e 987654321`

Return json data
`./QueryClient (insert any from above) -f json`
replace json with bin or verbose for other formats

### DiventiIP

When deciding upon an IP to use the script looks in
* /etc/diventi.conf
* .diventi.conf
* cli options

Each level down this list overrides the definitions of DiventiIP present above it. This is done to make defining the server ip less of a hassle

## secOrdConn.py
example of a script which finds all the first and second order connections of a certain ip address

```
	    1st   2nd
	   /     /
	ip -- 1st -- 2nd
	  \    \
	   \    2nd
	   1st -- 2nd
	     \ 
	      2nd
```

## binary_ex.py
	example of getting and parsing binary data from the server

## bin_functions.py
	functions used by binary_ex

## close_last_week.py
	example of querying server using for all records on a given ip which occurred within the last week

## json_ex.py
	example of getting and parsing json data from the server

## query_subnet.py
	example of a range query script

