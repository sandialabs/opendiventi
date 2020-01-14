"""
This code is for debugging purposes. It compares the output of queries to the expected results.
USAGE:
python3 test.py diventiIP
diventiIP is generally 0.0.0.0 for local tests like this but may differ by system
"""


import sys
import subprocess
import ipaddress
import requests
import time
import os

port = 41311 # diventi's port
path = os.getcwd()

if len(sys.argv) < 2:
	print(__doc__)
else:
	print("The server, at the provided ip will need to have the file conn.log loaded and have only that file")
	print("Querying server for the verification ip addresses and checking against expected results")
	print("Diff set to ignore whitespace\n")
	
	proxies = {'http': None }

	# Construct the query string
	addr = ["143.166.224.244", "192.168.1.1", "212.227.97.133", "224.0.0.251", "65.55.184.16"]
	#Create a list of the files to compare them against
	files = ["143.166.224.244-results.txt", "192.168.1.1-results.txt", "212.227.97.133-results.txt", "224.0.0.251-results.txt", "65.55.184.16-results.txt"]
	for i in range(0,5):
		print("FILE : " + addr[i])
		args = {"ip": str(addr[i]), "logs": "16690"}
		time.sleep(.25)
		# Send the query to diventi
		diventi_addr = sys.argv[1]
		try:
			r = requests.get("http://" + diventi_addr + ":" +str(port) + "/query", params=args, proxies=proxies)
			#save the text of the result to a file and prepare the expected result
			ret = r.text
			file = open(path + '/result.txt', 'w')
			file.write(ret)
			file.close()
			exp_ret = path + "/" + files[i];
			#call diff to find the differences between the files
			subprocess.run(["diff", "-w", exp_ret, path + "/result.txt"])
		except requests.exceptions.RequestException as e:
		    print(e)
