#! /usr/bin/python3
"""
Query diventi for ip related events. Such as netflow or bro-conn logs.
This script functions as a replacement for the now depricated ClientSideCli
"""

import sys
import argparse
import ipaddress
import requests
import json

import binary_handler

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('-d', dest='DB_IP', default='', help='The ip address of diventi server (required if not in conf file)')
parser.add_argument('queryIP', help='The ip address to query for')
parser.add_argument('-r', dest='range', default='', help='query from queryIP to range ip')
parser.add_argument('-s', dest='start', default='', help='query from this timestamp forward')
parser.add_argument('-e', dest='end', default='', help='query up to this timestamp')
parser.add_argument('-t', dest='type', default='none', help='format of the data, options: none(the default), json, bin, verbose')
parser.add_argument('-l', dest='logs', default=1000, help='number of logs to return from the db')
parser.add_argument('-p', dest='statistics', action='store_const', default=False, const=True, help='gather performance statistics if flag present')
parser.add_argument('-24', dest='last24', action='store_const', const=True, default=False, help='query on the last 24 hours')
parser.add_argument('-36', dest='last36', action='store_const', const=True, default=False, help='query on the last 36 hours')
parser.add_argument('-72', dest='last72', action='store_const', const=True, default=False, help='query on the last 72 hours')
parser.add_argument('-lw', '--lastweek', dest="lastweek", action='store_const', const=True, default=False, help='query on the last week of data')
parser.add_argument('-lm', '--lastmonth', dest="lastmonth", action='store_const', const=True, default=False, help='query on the last month of data')
parser.add_argument('--port', dest="port", default=41311, help="diventi port to query")
args = parser.parse_args()
proxies = {'http': None }


# Construct the query string
net = ipaddress.ip_network(args.queryIP, strict=False)
options = {"ip": str(net.network_address)}
port = args.port # diventi's port

if(args.range != ''):
    r = ipaddress.ip_network(args.range, strict=False)
    options["range"] = str(r.network_address)
if(args.start != ''):
    options["startTime"] = args.start
if(args.end != ''):
    options["endTime"] = args.end
if(args.type != ''):
    options["type"] = args.type
if(args.statistics == True):
    options["stats"] = args.statistics
if(args.logs != 1000):
    options["logs"] = args.logs


#In order of precedence, define the DB_IP
if(args.DB_IP == ''):
    #If not specified in cli, check for conf file in current dir
    try:
        results = None
        with open("~/.diventi.conf") as file:
            results = file.read()
    except:
        #if not specified in home directory then check /etc/diventi.conf
        try:
            with open("/etc/diventi.conf") as file:
                results = file.read()
        except:
            print("Diventi ip not defined and unsucessfully pulled from files")
            sys.exit()
        #if none of the above: error
        if results==None:
            print("Diventi ip not defined and unsucessfully pulled from files")
            sys.exit()
        args.DB_IP=results.strip()

# Send the query to diventi
diventi_addr = args.DB_IP

funcs = None
if (options['type'] == 'bin'):
    r = requests.get("http://" + diventi_addr + ":" +str(port) + "/query?sources", proxies=proxies)
    funcs = binary_handler.setupFormats(r.text)

# a function to take the response from diventi and check if there are more
# results that diventi wants to give us. If so, query for them
def checkCursor(text, type):
    def sendAnother(url):
        try:
            r = requests.get("http://" + diventi_addr + ":" +str(port) + url, proxies=proxies)
            checkCursor(r.text, type)
        except requests.exceptions.RequestException as e:
           print(e)

    if (type  == "json"):
        js = json.loads(text)
        if 'next' in js[0]:
            print(json.dumps(js[1:]))
            sendAnother(js[0]['next'])
        else:
            print(text)

    elif (type == "bin"):
        if (text[:7] == "/query?"):
            firstLine = text.split('\n', 1)[0]
            rest = text.split('\n',1)[1]
            binary_handler.printBinary(rest, funcs)
            sendAnother(firstLine)
        else:
            binary_handler.printBinary(text, funcs)

    else: # 'none' or 'verbose'
        if (text[:7] == "/query?"):
            firstLine = text.split('\n', 1)[0]
            rest = text.split('\n',1)[1]
            print(rest)
            sendAnother(firstLine)
        else:
            print(text)

if((args.start != '' or args.end != '') and args.range != '' and args.range != args.queryIP):
    print("Will break up a query of this type into multiple queries")
    for i in range(int(net.network_address), int(r.network_address) + 1):
        # print(i - int(net.network_address))
        query = ipaddress.ip_network(i, strict=False)
        options["ip"] = str(query.network_address)
        options["range"] = str(query.network_address)
        try:
            r = requests.get("http://" + diventi_addr + ":" +str(port) + "/query", params=options, proxies=proxies)
            if len(r.text) != 0:
                checkCursor(r.text, options["type"])
        except requests.exceptions.RequestException as e:
            print(e)
            sys.exit(1)

else:
    try:
        r = requests.get("http://" + diventi_addr + ":" +str(port) + "/query", params=options, proxies=proxies)
        checkCursor(r.text, options["type"])
    except requests.exceptions.RequestException as e:
        print(e)
        sys.exit(1)
