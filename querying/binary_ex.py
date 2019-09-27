"""
This script is used to test the functionality of the binary output

It will simply query for the provided ip at the provided server and can also query a range 
if the optional argument [range] is provided

USAGE:
python3 binary_ex.py diventiIP queryIP [range]
"""

import sys
import ipaddress
import requests
from bin_functions import *

#	An example of using bin_functions to output the result of a query

port = 41311 # diventi's port

proxies = {'http': None }

if len(sys.argv) < 3:
	print(__doc__)
else:
	# Construct the query string
	net = ipaddress.ip_network(sys.argv[2], strict=False)
	
	if len(sys.argv) == 3:
		args = (("ip", str(net.network_address)), ("type","bin"))
	else:
		netr = ipaddress.ip_network(sys.argv[3], strict=False)
		args = (("ip", str(net.network_address)), ("range", str(netr.broadcast_address)), ("type","bin"))
	# Send the query to diventi
	diventi_addr = sys.argv[1]
	newqueries = set()
	try:
		r = requests.get("http://" + diventi_addr + ":" +str(port) + "/query", params=args, proxies=proxies)
		answer = r.text
		cur_pos = 0
		line = 0
		while cur_pos < len(answer):
			#get the fields
			time, cur_pos = getTime(cur_pos,answer)
			oip, cur_pos = getOIP(cur_pos, answer)
			op, cur_pos = getOPort(cur_pos, answer)
			rip, cur_pos = getRIP(cur_pos, answer)
			rp, cur_pos = getRPort(cur_pos, answer)
			pro, cur_pos = getPro(cur_pos, answer)
			dur, cur_pos = getDur(cur_pos, answer)
			obyte, cur_pos = getOByte(cur_pos, answer)
			rbyte, cur_pos = getRByte(cur_pos, answer)
			conn, cur_pos = getConn(cur_pos, answer)
			#conn, cur_pos = getTCP(cur_pos, answer)
			opkts, cur_pos = getOPkts(cur_pos, answer)
			rpkts, cur_pos = getRPkts(cur_pos, answer)
			uid, cur_pos = getUID(cur_pos, answer)
			#print it out
			if ( line % 15 == 0):
				print("ts	     orig_ip       orig_port  resp_ip      resp_port    proto  duration  orig_bytes      resp_bytes  conn_state  orig_pkts       resp_pkts       uid")
			print(str(time) + " "*(13 - len(str(time))) + oip +" " * (17-len(oip)) + str(op) + " "*(7 - len(str(op))) + rip + " "*(17-len(rip))+ str(rp) + " "*(10 - len(str(rp))) + str(pro) + " "*(10-len(str(pro))) + str(dur) 
				+ " "*(7-len(str(dur))) + str(obyte) + " "*(16-len(str(obyte))) + str(rbyte) + " "*(16-len(str(rbyte))) + conn + " "*(8 - len(conn)) + str(opkts) + " "*(16-len(str(opkts))) + str(rpkts) + " "*(16-len(str(rpkts))) + uid)
			# print(str(time) + " "*(13 - len(str(time))) + oip +" " * (17-len(oip)) + str(op) + " "*(7 - len(str(op))) + rip + " "*(17-len(rip))+ str(rp) + " "*(10 - len(str(rp))) + str(pro) + " "*(10-len(str(pro))) + str(dur) 
			# 	+ " "*(7-len(str(dur))) + str(obyte) + " "*(16-len(str(obyte))) + str(rbyte) + " "*(16-len(str(rbyte))) + conn + " "*(8 - len(conn)) + str(opkts) + " "*(16-len(str(opkts))) + str(rpkts) + " "*(16-len(str(rpkts))))
			line += 1
	except requests.exceptions.RequestException as e:
	    print(e)
