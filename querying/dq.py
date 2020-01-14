#! /usr/bin/python
"""
Query diventi  for IP flows, typically from  netflow or bro-conn logs.
This script creates a simple CLI line to connect to create an http query to
the diventi server.

This script functions as a replacement for the now depricated ClientSideCli
"""

usage="""
dq is a tool to query a diventi server.

Some examples:
------------
IP point query
  dq <IP>
  dq  10.50.1.19      # search for just the .19 IP


Time Range
  dq -s 2017-10-31 <IP>  # all instances of IP since 2017-10-31
  dq -72 <IP>  # all instances of IP in the last 72 hours 


IP range examples
   dq  10.221.22.0/25    # search for .0-.127 subnet etc...
   dq -r <hiIP>  <lowIP>   # will search for all IPs between lowIP and hiIP  (inclusive)
   dq -r 255.255.255.255 0.0.0.0    # will search for all IP addresses seen.


"""

import sys
import os
import argparse
import pdb
import time
import json

import urllib
import urllib2

debug_level=0
def debug(string,level=50):
    """
    Debug output.
    """
    global debug_level
    
    if level < debug_level:
        print string

def int2ip_str(ip):
    """
    turn an int into a octet IP
    """
    a = ip & 0xff000000
    a = a >> 24
    b = ip & 0xff0000
    b = b >> 16
    c = ip & 0xff00
    c = c >> 8
    d = ip & 0xff
    s = "%d.%d.%d.%d" %(a,b,c,d)
   
    debug("ip string %ld  %s " %(ip,s), 40)
    return s

def ip2int(ip_str):
    """
    turn a string into a 
    """
    (a,b,c,d) = ip_str.split(".")
    r = long(d)
    r += (long(c) << 8)
    r += long(b) << 16
    r += long(a) << 24
    debug("ip2int  %s %s %s %s %ld " %(a,b,c,d,r), 40)
    return r

parser = argparse.ArgumentParser(description=usage,formatter_class=argparse.RawDescriptionHelpFormatter)

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
parser.add_argument('--debug', dest="debug",  default='0', help='Set the level of debug output')
args = parser.parse_args()
proxies = {'http': None }

port = args.port

if args.debug:
    debug_level = int(args.debug)
    print "Debug level set to: %d" %(debug_level)
#  
#   search for the server in a config file (if not in cli)
#
if(args.DB_IP == ''):
    #If not specified in cli, check for conf file in current dir
    debug("searching for server IP",30)
    try:
        results = None
        user_file = os.path.expanduser("~/.diventi.conf")
        with open(user_file) as file:
            results = file.read()
            debug("found user conf file w/ ip:"+results,50)
    except:
        #if not specified in home directory then check /etc/diventi.conf
        try:
            with open("/etc/diventi.conf") as file:
                results = file.read()
                debug("found host conf file w/ ip:"+results)
        except:
            print("Diventi ip not defined and unsucessfully pulled from files")
            sys.exit()
        #if none of the above: error
        if results==None:
            print("Diventi ip not defined and unsucessfully pulled from files")
            sys.exit()
            
    args.DB_IP=results.strip()
    debug("Using ip:"+args.DB_IP , 30)


#
#  Check for any of the time short hands and set start time to them.
#
if args.last24:
    args.start = str(time.time() - 60*60*24)
elif args.last36:
    args.start = str(time.time() - 60*60*36)

elif args.last72:
    args.start = str(time.time() - 60*60*72)

elif args.lastweek:
    args.start = str(time.time() - 60*60*24*7)
    
else:
    try:
        if args.start:
            if " " in args.start:
                start = time.strptime(args.start, "%Y-%m-%d %H:%M")
            else:
                start = time.strptime(args.start, "%Y-%m-%d")
            args.start = str(time.mktime(start))
    except:
        print "Unable to parse start time: %s should be YYYY-MM-DD [HH:MM]"
    
    try:
        if args.end:
            if " " in args.end:
                end = time.strptime(args.end, "%Y-%m-%d %H:%M")
            else:
                end = time.strptime(args.end, "%Y-%m-%d")
            args.end = str(time.mktime(end))
    except:
        print "Unable to parse start time: %s should be YYYY-MM-DD [HH:MM]"
    


#
#  Check if host IP is a subnet. then make it into a range search.
#    This code doesn't claim to perfectly parse but just splits at / and then rolls
#
if '/' in args.queryIP:
    try:
        ip_str,net_str = args.queryIP.split("/")
        ip = ip2int(ip_str)
    
        args.queryIP=ip_str

        bits = 32 - int(net_str)
        count = (2**bits) -1
        ip += count
    
        args.range = int2ip_str(ip)
        debug("Calc'd range: ip: %ld  count: %d  %s to %s"%(ip,count,args.queryIP,args.range),30) 
    except:
        print "Failed to parse ip range %s" % (args.queryIP)
        sys.exit()
        
    



# 
# Construct the query string as a list of options built into a
# url query string.

options = {"ip": args.queryIP} 
if(args.range != ''):
    options["range"] = args.range
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



#
#  Do basic query
#
params = urllib.urlencode(options)
url = "http://"+args.DB_IP +":"+str(port)+"/query?" + params

#import pdb
#pdb.set_trace()
debug("Query url is: %s"%(url),10)



    
#
#  Check if there is a special case of searching time and IP range then do it manually.
#
if((args.start != '' or args.end != '') and args.range != '' and args.range != args.queryIP):
    print("Sorry CLI currently not set up for range of IPs and range of time.")
    sys.exit(1)


#
#  Send the query to the server
#
while(True):
    req = urllib2.Request(url)
    try:
        response = urllib2.urlopen(req)
    except urllib2.HTTPError as e:
        print 'The server couldn\'t fulfill the request.'
        print 'Error code: ', e.code
    except urllib2.URLError as e:
        print 'We failed to reach a server.'
        print 'Reason: ', e.reason
    else:
        text = response.read()
        # everything is fine
        # handle the response
        if (type  == "json"):
            js = json.loads(text)
            if 'next' in js[0]:
                print json.dumps(js[1:])
                url = "http://" + args.DB_IP + ":" +str(port) + js[0]['next']
            else:
                print text
                break

        else: # "none", "verbose" or "binary"
            firstLine = text.split('\n', 1)[0]
            if (firstLine[:7] == "/query?"):
                rest = text.split('\n',1)[1]
                print rest
                url = "http://" + args.DB_IP + ":" +str(port) + firstLine
            else:
                print text
                break
    
