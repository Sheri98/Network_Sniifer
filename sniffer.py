#packet sniffer for eth ip and tcp/udp header 

#! usr/bin/python

import socket
import os
import struct
import binascii 

def analyse_ethr_header(data):
	ethr_header = struct.unpack("!6s6sH" , data[:14] )
	dst_mac     = binascii.hexlify(ethr_header[0])
	src_mac     = binascii.hexlify(ethr_header[1])
	proto	    = ethr_header[2]
	print  "=================================================ETHER HEADER DETAILS======================================================="
	print  "DESTINATION MAC :::: {0}:{1}:{2}:{4}:{5}:{6} ".format( dst_mac[0:2],dst_mac[2:4],dst_mac[4:6],dst_mac[4:6],dst_mac[6:8],dst_mac[8:10],dst_mac[10:12])
	print  "SOURCE MAC      :::: {0}:{1}:{2}:{4}:{5}:{6} ".format( src_mac[0:2],src_mac[2:4],src_mac[4:6],src_mac[4:6],src_mac[6:8],src_mac[8:10],src_mac[10:12])
	print  "PROTOCOL USED   :::: " + hex(proto)
	ip_bool = False		

	if hex(proto) == '0x800':
		ip_bool = True
		
	
	data= data[14:]

	return data,ip_bool


def analyze_ip_header(data):
	ip_header = struct.unpack("!6H4s4s",data[:20]);
	version   = ip_header[0] >> 12
	inthdrlen = (ip_header[0] >> 8) & 0x0f
	tos 	  = ip_header[0] & 0x00ff
	tolen 	  =  ip_header[1]
	identfctn = ip_header[2]
	flags	  = ip_header[3] >> 13
	fragntofst= ip_header[3] & 0x1fff
	tol 	  = ip_header[4] >> 8
	proto	  = ip_header[4] & 0x00ff
	cheksum   = ip_header[5] 
	src_adr	  =  socket.inet_ntoa(ip_header[6])
	dest_adr  =  socket.inet_ntoa(ip_header[7])
	print  "=================================================IP HEADER DEATILS======================================================="
	print "VERSION OF IP          :::: " + str(version)
	print "INTERNET HEADER LENGTH :::: " + str(inthdrlen)
	print "TYPE OF SERVICE 	      :::: " + str(tos)
	print "TOTAL LENGTH 	      :::: " + str(tolen)
	print "IDENTIFICATION NUMBER  :::: " + str(identfctn)
	print "FLAGS SET 	      :::: " + str(flags)
	print "TIME TO LEAVE 	      :::: " + str(tol)
	print "FRAGMENT OF SET 	      :::: " + str(fragntofst)
	print "PROTOCOL USED	      :::: " + str(proto)
	print "CHECK SUM 	      :::: " + str(cheksum)
	print "SOURCE IP ADDRESS      :::: " + str(src_adr)
	print "DESTINATION IP ADDRESS :::: " + str(dest_adr)
	
	next_proto = "" 
	if proto == 6:
		next_proto = "TCP"
	elif proto == 17:
		next_proto = "UDP" 
	data = data[20:]
	return data,next_proto


def analyze_tcp_header(data):
	tcp_header = struct.unpack('!2H2I4H',data[:20])
	src_port   = tcp_header[0]
	dst_port   = tcp_header[1]
	seqno	   = tcp_header[2]
	ackno 	   = tcp_header[3]
	offset 	   = tcp_header[4] >> 12
	reserved   = (tcp_header[4] >> 6 ) & 0x03ff
	flags  	   = tcp_header[4] &  0x003f
	urg 	   = flags & 0x0020
	ack 	   = flags & 0x0010
	psh 	   = flags & 0x0008
	rst 	   = flags & 0x0004
	syn 	   = flags & 0x0002
	fin	   = flags & 0x0001
	window 	   = tcp_header[5]
	checksum   = tcp_header[6]
	urgntpnter = tcp_header[7]
	print  "=================================================TCP HEADER DETAILS=======================================================" 
	print "SOURCE PORT           :::: " + str(src_port)
	print "DESTINATION PORT      :::: " + str(dst_port)
	print "SEQUENCE NUMBER       :::: " + str(seqno)
	print "ACKNOWLEDGMENT NUMBER :::: " + str(ackno)
	print "OFFSET  		     :::: " + str(offset)
	print "RESERVED     	     :::: " + str(reserved)
	if urg:
		print "URG FLAG IS SET" 
	if ack:
		print "ACK FLAG IS SET"
	if psh:
		print "PUSH FLAG IS SET"
	if rst:
		print "RESET FLAG IS SET"
	if syn:
		print "SYN FLAG  IS SET"
	if fin:
		print "FIN FLAG IS SET"

	print "WINDOW LENGTH  	     :::: " + str( window)
	print "CHECK SUM 	     :::: " + str(checksum)
	print "URGENT POINTER 	     :::: " + str(urgntpnter)

	data = data[:20]
	return data


def analyze_udp_header(data):

	udp_header = struct.unpack("!4H",data[:8])
	src_port   = udp_header[0]
	dst_port   = udp_header[1]
	length	   = udp_header[2]
	checksum   = udp_header[3]
	print  "=================================================UDP HEADER DETAILS======================================================="
	print "SOURCE PORT 	      :::: " + str(src_port)
	print "DESTIONATION PORT      :::: " + str(dst_port)
	print "LENGTH 		      :::: " + str(length)
	print "CHECK SUM 	      :::: " + str(checksum)

	data = data[8:]
	return data

def main():
	ssk_sniffer = socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.htons(0x003))
	recv_data   = ssk_sniffer.recv(2048)
	os.system('clear')
	data,ip_bool = analyse_ethr_header(recv_data)
	next_proto = ''
	if ip_bool:
		data,next_proto = analyze_ip_header(data)
		
	if next_proto == 'TCP':
		data = analyze_tcp_header(data)
	elif next_proto == 'UDP':
		data = analyze_udp_header(data)

while True:
	main()
