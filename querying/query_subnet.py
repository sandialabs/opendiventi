"""
This script demonstrates the construction and sending of a query for activity on a subnet.
Requires the ipaddress module, which is included by default in Python 3.

Usage:
	python3 query_subnet.py diventi_ip query_ip
"""

import sys
import ipaddress
import requests

port = 41311 # diventi's port

proxies = {'http': None }

if len(sys.argv) < 3:
	print(__doc__)
else:
	# Construct the query string
	net = ipaddress.ip_network(sys.argv[2], strict=False)
	args = {"ip": str(net.network_address)}

	# Send the query to diventi
	diventi_addr = sys.argv[1]
	try:
		r = requests.get("http://" + diventi_addr + ":" +str(port) + "/query", params=args, proxies=proxies)
		print(r.text)
	except requests.exceptions.RequestException as e:
	    print(e)