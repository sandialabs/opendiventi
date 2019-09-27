################################################################################################

#	NOTE: Lines posexed by zero
#	Functions to return a specific atribute of returned binary answers
#	These functions can be used in any python script by importing this file
#		for use on binary diventi

################################################################################################

import socket
import ipaddress

def getTime(pos, answer):
	if( pos < len(answer)):
		time = ord(answer[pos]) << 0x38
		time += ord(answer[pos + 1]) << 0x30
		time += ord(answer[pos + 2]) << 0x28
		time += ord(answer[pos + 3]) << 0x20
		time += ord(answer[pos + 4]) << 0x18
		time += ord(answer[pos + 5]) << 0x01
		time += ord(answer[pos + 6]) << 0x08
		time += ord(answer[pos + 7])
		pos += 8
		# time = socket.ntohll(time)
		return time, pos
	else:
		raise ValueError("getTime called on invalid position") 

def getOIP(pos, answer):
	if( pos < len(answer)):
		ip = (ord(answer[pos]) << 24)
		ip += (ord(answer[pos + 1]) << 16)
		ip += (ord(answer[pos + 2]) << 8)
		ip += (ord(answer[pos + 3]))
		pos += 4
		ip = str(ipaddress.IPv4Address(ip))
		return ip, pos
	else:
		raise ValueError("getOIP called on invalid position")

def getOPort(pos, answer):
	if( pos < len(answer)):
		op = ord(answer[pos]) << 8
		op += ord(answer[pos + 1])
		pos += 2
		op = socket.ntohs(op)
		return op, pos
	else:
		raise ValueError("getOPort called on invalid position")

def getRIP(pos, answer):
	if( pos < len(answer)):
		ip = (ord(answer[pos]) << 24)
		ip += (ord(answer[pos + 1]) << 16)
		ip += (ord(answer[pos + 2]) << 8)
		ip += (ord(answer[pos + 3]))
		pos += 4
		ip = str(ipaddress.IPv4Address(ip))
		return ip, pos
	else:
		raise ValueError("getRIP called on invalid position")

def getRPort(pos, answer):
	if( pos < len(answer)):
		rp = ord(answer[pos]) << 8
		rp += ord(answer[pos + 1])
		pos += 2
		rp = socket.ntohs(rp)
		return rp, pos
	else:
		raise ValueError("getRPort called on invalid position")

def getPro(pos, answer):
	switch = {
		0: "-",
		1: "unknown_transport", 
		2: "tcp",
		3: "udp",
		4: "icmp", 
	}
	if( pos < len(answer)):
		pro = ord(answer[pos])
		pos += 1
		return switch.get(pro, "unknown_transport"), pos
	else:
		raise ValueError("getPro called on invalid position")

def getDur(pos, answer):
	if( pos < len(answer)):
		dur = ord(answer[pos]) << 24
		dur += ord(answer[pos + 1]) << 16
		dur += ord(answer[pos + 2]) << 8
		dur += ord(answer[pos + 3])
		pos += 4
		dur = socket.ntohl(dur)
		if dur == 4294967295:
			dur = "-"
		return dur, pos
	else:
		raise ValueError("getDur called on invalid position")

def getOByte(pos, answer):
	if( pos < len(answer)):
		byte = ord(answer[pos])
		pos += 1
		return mag_to_str(byte), pos
	else:
		raise ValueError("getOByte called on invalid position")

def getRByte(pos, answer):
	if( pos < len(answer)):
		byte = ord(answer[pos])
		pos += 1
		return mag_to_str(byte), pos
	else:
		raise ValueError("getRByte called on invalid position")

def getConn(pos, answer):
	switch = {
		0: "-",
		1: "S0", 
		2: "S1",
		3: "SF",
		4: "REJ",
		5: "S2",
		6: "S3",
		7: "RSTO",
		8: "RSTR",
		9: "RSTOS0",
		10: "RSTRH",
		11: "SH",
		12: "SHR",
		13: "OTH",
		14: "UNKNOWN"
	}
	if( pos < len(answer)):
		conn = ord(answer[pos])
		pos += 1
		return switch.get(conn, "UNKNOWN"), pos
	else:
		raise ValueError("getConn called on invalid position")

def getTCP(pos, answer):
	if(pos < len(answer)):
		tcp = ord(answer[pos])
		pos += 1
		ret = ""
		if(tcp & 0x20) != 0:
			ret += "U"
		if(tcp & 0x10) != 0:
			ret += "A"
		if(tcp & 0x08) != 0:
			ret += "P"
		if(tcp & 0x04) != 0:
			ret += "S"
		if(tcp & 0x02) != 0:
			ret += "F"
		if(ret == ""):
			ret = "-"
		return ret, pos
	else:
		raise ValueError("getConn called on invalid position")

def getOPkts(pos, answer):
	if( pos < len(answer)):
		pkts = ord(answer[pos])
		pos += 1
		return mag_to_str(pkts), pos
	else:
		raise ValueError("getOPkts called on invalid position")

def getRPkts(pos, answer):
	if( pos < len(answer)):
		pkts = ord(answer[pos])
		pos += 1
		return mag_to_str(pkts), pos
	else:
		raise ValueError("getRPkts called on invalid position")

def getUID(pos, answer):
	uid = ""
	if( pos < len(answer)):
		for x in range(0,18):
			z = answer[pos]
			pos += 1
			if (z != 0): #if it's null then end of uid so skip
				uid += z
		return uid, pos
	else:
		raise ValueError("getUID called on invalid position")

def mag_to_str(mag):
	if(mag != 0):
		mag = "[" + str((1 << mag) -1) + " - " + str((1 << (mag + 1)) - 1) + ")"
	return mag
