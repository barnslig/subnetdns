# -*- coding: utf-8 -*-
from dnslib import *
import json, sys, socket, re, hashlib, netaddr, base64

# dirtiest utf8 hack ever
reload(sys)
sys.setdefaultencoding("utf-8")

# read the configuration
config = json.loads(open(sys.argv[1], "r").read())

# open the socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((config["daemon"]["bind"], int(config["daemon"]["port"])))

# function to create an ipv6 address from the reverse name
def ipv6FromArpa(name):
	# make the long ipv6 address from the dns string
	name = name.replace(".ip6.arpa", "")
	name = name.split(".")
	name.reverse()
	name = "".join(name)
	name = re.findall("....", name)
	name = ":".join(name)
	# shorten it
	ip = netaddr.IPAddress(name)
	ip = str(ip.ipv6())
	
	return ip

# function to create an ipv4 address from the reverse name
def ipv4FromArpa(name):
	name = name.replace(".in-addr.arpa", "")
	name = name.split(".")
	name.reverse()
	name = ".".join(name)
	
	return name

def dns_handler(data):
	print len(data)
	request = DNSRecord.parse(data)
	id = request.header.id
	qname = request.q.qname
	qtype = request.q.qtype
	successfull = False
	
	# REVERSE
	if request.q.qtype == QTYPE.PTR:
		ptr = request.q.qname.__str__()
		# ipv6
		if "ip6.arpa" in ptr:
			addr = netaddr.IPAddress(ipv6FromArpa(ptr))
			# check if the address is in a subnet
			for net in config["ipv6"]:
				netZ = netaddr.IPNetwork(net)
				if addr in netZ:					
					ptrA = config["ipv6"][net].replace("%%digits%%", "6" + base64.b16encode(str(addr))).encode("utf-8")
					
					reply = DNSRecord(DNSHeader(id=id, qr=1, aa=1, ra=1), q=request.q)
					reply.add_answer(RR(qname, qtype, rdata=PTR(ptrA)))
					
					successfull = True
			
		# ipv4
		elif "in-addr.arpa" in ptr:
			addr = netaddr.IPAddress(ipv4FromArpa(ptr))
			# check if the address is in a subnet
			for net in config["ipv4"]:
				netZ = netaddr.IPNetwork(net)
				if addr in netZ:
					ptrA = config["ipv4"][net].replace("%%digits%%", "4" + str(addr).replace(".", "-")).encode("utf-8")
					
					reply = DNSRecord(DNSHeader(id=id, qr=1, aa=1, ra=1), q=request.q)
					reply.add_answer(RR(qname, qtype, rdata=PTR(ptrA)))
					
					successfull = True

	# address to name
	elif request.q.qtype == QTYPE.A:
		a = request.q.qname.__str__()
		v6 = False
		
		for net in config["ipv4"]:
			y = config["ipv4"][net].split("%%digits%%")
			x = a.replace(y[0], "")
			if x[0:1] == "4":
				x = x.replace(y[1], "")
				x = x.replace("-", ".")
				if netaddr.IPAddress(x) in netaddr.IPNetwork(net):
					reply = DNSRecord(DNSHeader(id=id, qr=1, aa=1, ra=1), q=request.q)
					reply.add_answer(RR(qname, qtype, rdata=A(x)))
					
					successfull = True
			else:
				v6 = True
				break
		
		if v6:
			for net in config["ipv6"]:
				y = config["ipv6"][net].split("%%digits%%")
				x = a.replace(y[0], "")
				if x[0:1] == "6":
					x = x.replace(y[1], "")[1:90000000]
					x = base64.b16decode(x)
					if netaddr.IPAddress(x) in netaddr.IPNetwork(net):
						reply = DNSRecord(DNSHeader(id=id, qr=1, aa=1, ra=1), q=request.q)
						reply.add_answer(RR(qname, 28, rdata=AAAA(x)))
						
						successfull = True
	
	if not successfull:
		reply = DNSRecord(DNSHeader(id=id, qr=1, aa=1, ra=1, rcode=3), q=request.q)
	
	return reply.pack()

while True:
	data, addr = s.recvfrom(8192)
	packet = dns_handler(data)
	s.sendto(packet, addr)
