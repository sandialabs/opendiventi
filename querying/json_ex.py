"""
This script is used to test the functionality of the new computer readable
json output

Currnently it is simply another means for Evan to mess around with the json side of things

USAGE:
python3 json_ex.py diventiIP queryIP
"""

import sys
import ipaddress
import requests
import json

port = 41311 # diventi's port

proxies = {'http': None }

if len(sys.argv) < 3:
	print(__doc__)
else:
	# Construct the query string
	net = ipaddress.ip_network(sys.argv[2], strict=False)
	args = (("ip", str(net.network_address)), ("type","json"))

	# Send the query to diventi
	diventi_addr = sys.argv[1]
	try:
		r = requests.get("http://" + diventi_addr + ":" +str(port) + "/query", params=args, proxies=proxies)
		ret = r.text
		answer = json.loads(ret);
		for i in answer:
			print(i['key']['timestamp'], end=' ')
			print(i['key']['id.orig_h'], end=' ')
			print(i['key']['id.orig_p'], end=' ')
			print(i['key']['id.resp_h'], end=' ')
			print(i['key']['id.resp_p'], end=' ')
			print(i['value']['protocol'], end=' ')
			print(i['value']['duration'], end=' ')
			print(i['value']['origin_bytes'], end=' ')
			print(i['value']['orig_pkts'], end=' ')
			print(i['value']['resp_bytes'], end=' ')
			print(i['value']['resp_pkts'], end=' ')
			print(i['value']['conn_state'], end=' ')
			print(i['value']['uid'])
	except requests.exceptions.RequestException as e:
	    print(e)