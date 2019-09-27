"""
This script is used to test the functionality of the json output

It grabs all logs that contain a certain ip address eliminates all logs where this ip was the resp
Then it runs queries on all ip addresses that this one connected to

USAGE:
python3 secOrdConn.py diventiIP queryIP verbose('true'/'false') direction('out'/'in')
"""

import sys
import ipaddress
import requests
import json

port = 41311 # diventi's port

proxies = {'http': None }

if len(sys.argv) < 5:
	print(__doc__)
else:
	# Construct the query string
	net = ipaddress.ip_network(sys.argv[2], strict=False)
	args = (("ip", str(net.network_address)), ("range", str(net.broadcast_address)), ("type","json"))

	#Setup direction of flow variables
	dirc = sys.argv[4]

	# Send the query to diventi
	diventi_addr = sys.argv[1]
	newqueries = set()
	try:
		r = requests.get("http://" + diventi_addr + ":" +str(port) + "/query", params=args, proxies=proxies)
		ret = r.text
		answer = json.loads(ret);
		#loop through each given answer and check if it's origin is the ip we want
		count = 0
		for i in answer:
			oip = i['key']['id.orig_h']
			rip = i['key']['id.resp_h']
			if oip == str(net.network_address) and dirc == "out":
				newqueries.add(rip)
				count += 1
			elif rip == str(net.network_address) and dirc == "in":
				newqueries.add(oip)
				count += 1
	except requests.exceptions.RequestException as e:
	    print(e)
	if (dirc == "out"):
		print("Non-unique first order connections(ip -> x): " + str(count))
	else:
		print("Non-unique first order connections(x -> ip): " + str(count))
	print("\nUnique connections:")
	for x in newqueries:
		if( x == str(net.network_address) ):
			print("self:", end=' ')
		print(x)
	ncount = 0
	secCon = set()
	for x in newqueries:
		if(str(sys.argv[3]) == "true"):
			print("\n=============== " + x + " ==============="+"\n")
		try:
			args = (("ip", x), ("range", x), ("type","json"))
			r = requests.get("http://" + diventi_addr + ":" +str(port) + "/query", params=args, proxies=proxies)
			ret = r.text
			answer = json.loads(ret);
			#loop through each given answer and check if it's origin is the ip we want
			for i in answer:
				#print out all logs where x was the originator
				oip = i['key']['id.orig_h']
				rip = i['key']['id.resp_h']
				if((x == oip and dirc == "out") or (dirc == "in" and x == rip)) and str(sys.argv[3]) == "true":
					print(i['key']['timestamp'], end='  ')
					print(i['key']['id.orig_h'], end= '\t')
					print(i['key']['id.orig_p'], end='\t')
					print(i['key']['id.resp_h'], end='\t')
					print(i['key']['id.resp_p'], end=' ')
					print(i['value']['protocol'], end=' ')
					print(i['value']['duration'], end='\t')
					print(i['value']['origin_bytes'], end='\t\t')
					print(i['value']['orig_pkts'], end='\t\t')
					print(i['value']['resp_bytes'], end='\t')
					print(i['value']['resp_pkts'], end='\t\t')
					print(i['value']['conn_state'], end='\t')
					print(i['value']['uid'])
				if(x == oip and dirc == "out"):
					ncount += 1
					secCon.add(rip)
				elif(x == rip and dirc == "in"):
					ncount += 1
					secCon.add(oip)
		except requests.exceptions.RequestException as e:
		    print(e)
	if(dirc == "out"):
		print("\nNon-unique second order connections(x -> y): " + str(ncount))
	else:
		print("\nNon-unique second order connections(y -> x): " + str(ncount))
	print("\nUnique connections:")
	for x in secCon:
		print(x, end=' ')
		if( x == str(net.network_address) ):
			print("(SELF)")
		else:
			print()
