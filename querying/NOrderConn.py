#! /usr/bin/python3

"""
This script checks for all the records of a certain ip address and for all the
Records that have interacted with it within N interactions

It grabs all logs that contain a certain ip address
Then it runs queries on all ip addresses that this one connected to

"""

import sys
import ipaddress
import requests
import json
import argparse
# import matplotlib.pyplot as plt
import networkx as nx

def order(x):
	if x == 1:
		return 'first'
	elif x == 2:
		return 'second'
	elif x == 3:
		return 'third'
	elif x == 4:
		return 'fourth'
	elif x == 5:
		return 'fifth'
	elif x == 6:
		return 'sixth'
	else:
		return str(x) + '-th'

port = 41311 # diventi's port

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('DB_IP', help='The ip address of diventi server (required if not in conf file)')
parser.add_argument('queryIP', help='The ip address to query for')
parser.add_argument('N', help='search for N-order connections')
parser.add_argument('-r', dest='range', default='', help='query from queryIP to range ip')
parser.add_argument('-s', dest='start', default='', help='query from this timestamp forward')
parser.add_argument('-e', dest='end', default='', help='query up to this timestamp')
parser.add_argument('-d', dest='dirc', default='out', help="which direction should the hops take. Traffic coming 'in' or traffic going 'out'")
parser.add_argument('-g', dest='graph', const=True, default=False, action='store_const', help="build and display a graph of this data")
args = parser.parse_args()

proxies = {'http': None }

#The graph that will be built of the data if requested
G=nx.Graph()

net = ipaddress.ip_network(args.queryIP, strict=False)
options = {"ip": str(net.network_address)}
if(args.range != ''):
	r = ipaddress.ip_network(args.range, strict=False)
	options["range"] = str(r.network_address)
if(args.start != ''):
	options["startTime"] = args.start
if(args.end != ''):
	options["endTime"] = args.end

options['type'] = 'json'
# if(args.form != ''):
#         options["type"] = args.form
# if(args.statistics == True):
#         options["stats"] = args.statistics

#Setup direction of flow variables
dirc = args.dirc
hops = int(args.N)

# Send the query to diventi
connections = [set() for _ in range(hops)]
try:
	r = requests.get("http://" + args.DB_IP + ":" +str(port) + "/query", params=options, proxies=proxies)
	ret = r.text
	answer = json.loads(ret);
	#loop through each given answer and check if it's origin is the ip we want
	count = 0
	for i in answer:
		x = str(net.network_address)
		oip = i['key']['id.orig_h']
		rip = i['key']['id.resp_h']
		if((x == oip and dirc == "out") or (dirc == "in" and x == rip)) and args.verbose == True:
			print(i['key']['timestamp'], end='  ')
			print(i['key']['id.orig_h'], end= '\t')
			print(i['key']['id.orig_p'], end='\t')
			print(i['key']['id.resp_h'], end='\t')
			print(i['key']['id.resp_p'], end=' ')
			print(i['value']['protocol'], end=' ')
			print(i['value']['duration'], end='\t')
			print(i['value']['bytes'], end='\t\t')
			print(i['value']['pkts'], end='\t\t')
			print(i['value']['conn_state'])
		if oip == x and dirc == "out":
			connections[0].add(rip)
			count += 1
		elif rip == x and dirc == "in":
			connections[0].add(oip)
			count += 1
except requests.exceptions.RequestException as e:
    print(e)
if args.verbose:
	print()
if (dirc == "out"):
	print("Non-unique first order connections(ip -> 1): " + str(count))
else:
	print("Non-unique first order connections(1 -> ip): " + str(count))
print("Unique connections:")
for x in connections[0]:
	if( x == str(net.network_address) ):
		print("self:", end=' ')
	print(x)

for hop in range(1, hops):
	ncount = 0
	#for each thing in the previous set of connections. Run a query on it
	if args.verbose:
		print("\n++++++++++Querying Unique Connections(hop " + str(hop) + ") ++++++++++")
	for x in connections[hop-1]:
		if args.verbose:
			print("\n=============== " + x + " ===============")
		try:
			print()
			options['ip'] = x
			options['range'] = x
			r = requests.get("http://" + args.DB_IP + ":" +str(port) + "/query", params=options, proxies=proxies)
			ret = r.text
			answer = json.loads(ret);
			#loop through each given answer and check if it's origin is the ip we want
			for i in answer:
				#print out all logs where x was the originator
				oip = i['key']['id.orig_h']
				rip = i['key']['id.resp_h']
				if((x == oip and dirc == "out") or (dirc == "in" and x == rip)) and args.verbose == True:
					print(i['key']['timestamp'], end='  ')
					print(i['key']['id.orig_h'], end= '\t')
					print(i['key']['id.orig_p'], end='\t')
					print(i['key']['id.resp_h'], end='\t')
					print(i['key']['id.resp_p'], end=' ')
					print(i['value']['protocol'], end=' ')
					print(i['value']['duration'], end='\t')
					print(i['value']['bytes'], end='\t\t')
					print(i['value']['pkts'], end='\t\t')
					print(i['value']['conn_state'])
				if(x == oip and dirc == "out"):
					ncount += 1
					connections[hop].add(rip)
				elif(x == rip and dirc == "in"):
					ncount += 1
					connections[hop].add(oip)
		except requests.exceptions.RequestException as e:
		    print(e)
	if args.verbose:
		print("\nResults of above queries:")
	if(dirc == "out"):
		print("Non-unique " + order(hop + 1) + " order connections(" + str(hop) + " -> " + str(hop + 1) + "): " + str(ncount))
	else:
		print("Non-unique " + order(hop + 1) + " order connections(" + str(hop + 1) + " -> " + str(hop) + "): " + str(ncount))
	print("Unique connections:")
	for x in connections[hop]:
		print(x, end=' ')
		if( x == str(args.queryIP) ):
			print("(SELF)")
		else:
			print()
