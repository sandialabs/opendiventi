"""
Queries for any activity within the last week from the given ip.
Requires the ipaddress module, which is included by default in Python 3.

Usage:
	python3 close_last_week.py diventi_ip query_ip
"""

import sys
import ipaddress
import requests
import time

port = 41311 # diventi's port
week = 24 * 3600	# A week's worth of seconds

proxies = {'http': None }

if len(sys.argv) < 3:
	print(__doc__)
else:
	# Construct the query string
	addr = ipaddress.ip_address(sys.argv[2])
	now = int(time.time())
	args = {"ip": str(addr), "startTime": now - week, "endTime": now}

	# Send the query to diventi
	diventi_addr = sys.argv[1]
	try:
		r = requests.get("http://" + diventi_addr + ":" +str(port) + "/query", params=args, proxies=proxies)
		print(r.text)
	except requests.exceptions.RequestException as e:
	    print(e)