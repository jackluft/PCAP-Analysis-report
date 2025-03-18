#Jack Luft
#CSC 490 - March 2025
from scapy.all import *
import argparse
import matplotlib.pyplot as plt
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer, Image, Table, ListFlowable, ListItem
from reportlab.platypus.flowables import HRFlowable
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus.tables import TableStyle
from reportlab.lib import colors
from colorama import Fore
import sys
import numpy as np


#List of all packets
icmp_list = []
quic_list = []
arp_list = []
http_list = []
tcp_list = []
udp_list = []
dns_list = []
mdns_list = []
packet_number = 0
other_packets = []

#output file name
FILE_NAME = "output-report.pdf"

#Graph Colors
COLORS = ["Red", "Blue", "Green", "Cyan", "Orange", "Purple", "Pink", "Yellow", "Teal"]

class TCP_packet:
	def __init__(self,packet):
		self.packet = packet
		self.syn = True
		self.ack = False

	def handshake_completed(self):
		return self.syn and self.ack
	def complete_handshake(self):
		self.ack = True
	def getSrc(self):
		return self.packet[IP].src
	def getDst(self):
		return self.packet[IP].dst
	def getTime(self):
		return self.packet[IP].time

def calculate_percentage_of_syn(tcp_handshakes):
	#func: calculate_percentage_of_syn
	#args: tcp_handshakes -> list of tcp handshakes.
	#Docs: This function is a helper function for 'check_syn_flood()'
	#Its calculates the percentage of incomplete handshake in TCP traffic
	c = 0
	for t in tcp_handshakes:
		if t.syn == True and t.ack == False:
			c = c +1
	syn_percentage = c / len(tcp_list)
	return syn_percentage
def calculate_syn_from_ips(tcp_handshakes):
	#func: calculate_syn_from_ips
	#args: tcp_handshakes -> list of tcp handshakes
	#Docs: This function is a helper function for check_syn_flood()'
	#This function will return a list of all the ips, that for preforming the DDoS attack.
	syn_list_ips = []
	#{"IP": p, "count": x}
	for p in tcp_handshakes:
		if p.ack == False:
			found = False

			#Check if ip already in list
			for entry in syn_list_ips:
				if entry["packet"].getSrc() == p.getSrc():
					entry["count"] = entry["count"] +1
					entry["total bytes"] = entry["total bytes"] + len(p.packet)
					packet_time = p.getTime()
					entry["End time"] = packet_time
					found = True
					break
			if not found:
				#add it to the list
				packet_time = p.getTime()
				syn_list_ips.append({"packet":p, "count":1, "total bytes": len(p.packet), "Start Time": packet_time, "End time": packet_time})
				target_ip = p.getDst()
				target_port = p.packet.dport
	return syn_list_ips, target_ip,target_port
def calculate_syn_burst():
	#func: calculate_syn_burst
	#args: None
	#Docs: This function is a helper function for check_syn_flood()'
	#This function will calculate if the packet data has a bursty behavior 
	pass
def check_syn_flood():
	#func: syn_flood
	#args: None
	#Docs: This function will detected SYN flood attacks in the pcap file.

	OUTPUT_REPORT = {"SYN FLOOD DETECTED": False}
	#Check 1: First check what percentage of tcp is a uncomplete 3-way handsahke
	#Check 2: Check how many different IPs the attack is coming from
	#Check 3: Check if its a bursty behavior
	if len(tcp_list) > 0:
		tcp_handshakes = []
		timestamps = []
		for p in tcp_list:
			if p[TCP].flags == 0x02:
				#SYN packet
				#record the a SYN flag being sent
				tcp = TCP_packet(p)
				tcp_handshakes.append(tcp)
				timestamps.append(p.time)
			elif p[TCP].flags == 0x10:
				#ACK - That is completing the hand shake
				#Check if packet is in the tcp_syn list
				for tcp in tcp_handshakes:
					if p.src == tcp.getSrc() and p.dst == tcp.getDst():
						tcp.ack = True

		#After looping throw all the packets
		#see how many tcp handshakes have not been completed
		#log all the ip address that sent the SYN packets
		#Check 1
		syn_percentage = calculate_percentage_of_syn(tcp_handshakes)
		if syn_percentage > 0.3:
			#SYN_flood
			OUTPUT_REPORT["SYN FLOOD DETECTED"] = True
			#Check 2
			syn_list_ips,target_ip,target_port = calculate_syn_from_ips(tcp_handshakes)
			OUTPUT_REPORT["packets"] = syn_list_ips
			#Check 3: Bursty
			if timestamps:
				#Calculate packet rate
				first_time = timestamps[0]
				last_time = timestamps[-1]
				total = 0
				for p in syn_list_ips:
					total = total + p["count"]
				packet_rate = total / (last_time-first_time)
				OUTPUT_REPORT["packet rate"] = packet_rate
				OUTPUT_REPORT["target ip"] = target_ip
				OUTPUT_REPORT["target port"] = target_port
			calculate_syn_burst()
		OUTPUT_REPORT["SYN Flood percentage"] = syn_percentage
	else:
		OUTPUT_REPORT["SYN Flood percentage"] = 0
	return OUTPUT_REPORT
def check_http_get_flood():
	#func: check_http_get_flood
	#args: None
	#Doc: This function will detect if there is a HTTP-GET flood attack in the PCAP file.
	OUTPUT_REPORT = {"HTTP-GET FLOOD DETECTED": False}
	return OUTPUT_REPORT
def get_icmp_echo_packets():
	#func: get_icmp_echo_packets
	#args: None
	#Docs: This function will only get ICMP echo packets.
	#ICMP echo packets are used in DDoS attack where a attack sends echo packets
	echo_packets = []
	for p in icmp_list:
		if p[ICMP].type == 8:
			echo_packets.append(p)

	return echo_packets
def calculate_avg_ehco_icmp_packet_rate():
	#func: calculate_avg_icmp_packet_rate
	#args: None
	#Docs: This function will calculate the average packet rate for the ICMP DDoS attack.
	icmp_echo_list = get_icmp_echo_packets()
	timestamps = []
	for p in icmp_echo_list:
		timestamps.append(p.time)

	if timestamps:
		total_packets = len(icmp_echo_list)
		if(total_packets) > 1:
			first_time = timestamps[0]
			last_time = timestamps[-1]
			duration = last_time - first_time
			return total_packets / (duration)

	return 1
def calculate_avg_udp_packet_rate(list_of_udp):
	#func: calculate_avg_udp_packet_rate
	#args: 
	#Docs: This function will calculate the average packet rate for the UDP DDoS attack.
	#Make changes here
	timestamps = []
	for p in list_of_udp:
		timestamps.append(p.time)

	if timestamps:
		total_packets = len(list_of_udp)
		if(total_packets) > 1:
			first_time = timestamps[0]
			last_time = timestamps[-1]
			duration = last_time - first_time
			return total_packets / (duration)

	return 1
def calculate_icmp_from_ips():
	#func: calculate_syn_from_ips
	#args: tcp_handshakes -> list of tcp handshakes
	#Docs: This function is a helper function for check_syn_flood()'
	#This function will return a list of all the ips, that for preforming the DDoS attack.
	icmp_list_group = []
	icmp_echo_list = get_icmp_echo_packets()
	target_ip = None
	#{"IP": p, "count": x}
	for p in icmp_echo_list:
		found = False
		#Check if ip already in list
		for entry in icmp_list_group:
			if entry["packet"][IP].src == p[IP].src:
				entry["count"] = entry["count"] +1
				entry["total bytes"] = entry["total bytes"] + len(p)
				entry["End time"] = p.time
				found = True
				break
		if not found:
			#add it to the list
			packet_time = p.time
			icmp_list_group.append({"packet":p, "count":1, "total bytes": len(p), "Start Time": packet_time, "End time": packet_time})
			target_ip = p[IP].dst
	return icmp_list_group, target_ip
def get_icmp_flood_packets(icmp_packets):
	#func: get_icmp_flood_packets
	#args: icmp_packets -> 
	#Docs: This function will return a list of all the IPs (ICMP) that have a high packet rate
	#Check the ICMP burst rate
	burst_threshold = 100
	icmp_flood = []
	for p in icmp_packets:
		#Calculate packet rate
		#(endtime - start time) / packetnum
		if p["count"] > 1:
			icmp_rate = p["count"]/(p["End time"] - p["Start Time"])
		else:
			icmp_rate = p["count"]
		if icmp_rate > burst_threshold:
			#Packet is ICMP packet
			icmp_flood.append(p)
	return icmp_flood
def check_icmp_flood():
	#func: icmp_flood
	#args: None
	#Docs: This function will detect if there is an ICMP flood attack in the PCAP file.
	OUTPUT_REPORT = {"ICMP FLOOD DETECTED": False}
	icmp_packets, target_ip  = calculate_icmp_from_ips()
	#Check the ICMP burst rate
	icmp_flood = get_icmp_flood_packets(icmp_packets)

	#
	if len(icmp_flood) > 0:
		OUTPUT_REPORT["ICMP FLOOD DETECTED"] = True
		OUTPUT_REPORT["target ip"] = target_ip
		OUTPUT_REPORT["packets"] = icmp_flood
		OUTPUT_REPORT["avg packet rate"] = calculate_avg_ehco_icmp_packet_rate()



	return OUTPUT_REPORT
def calculate_udp_from_ips():
	#func: calculate_udp_from_ips
	#args: None
	#Docs: This function will return a list of ips that have sent multiple packets.
	#Will return the format: {"packet":p, "count":1, "total bytes": len(p), "Start Time": packet_time, "End time": packet_time}
	udp_list_group = []
	target_ip = None
	#{"IP": p, "count": x}
	for p in udp_list:
		found = False
		#Check if ip already in list
		for entry in udp_list_group:
			if(entry["packet"].haslayer(IPv6) and p.haslayer(IP)) or (entry["packet"].haslayer(IP) and p.haslayer(IPv6)):
				continue
			if entry["packet"].haslayer(IPv6):
				if entry["packet"][IPv6].src == p[IPv6].src:
					entry["count"] = entry["count"] +1
					entry["total bytes"] = entry["total bytes"] + len(p)
					entry["End time"] = p.time
					found = True
					break
			else:
				if entry["packet"][IP].src == p[IP].src:
					entry["count"] = entry["count"] +1
					entry["total bytes"] = entry["total bytes"] + len(p)
					entry["End time"] = p.time
					found = True
					break
		if not found:
			#add it to the list
			packet_time = p.time
			udp_list_group.append({"packet":p, "count":1, "total bytes": len(p), "Start Time": packet_time, "End time": packet_time})
			print(len(udp_list))
			print(list(expand(p)))
			if p.haslayer(IPv6):
				target_ip = p[IPv6].dst
			else:
				target_ip = p[IP].dst
	return udp_list_group, target_ip
def get_udp_flood_packets(udp_packets):
	#func: get_udp_flood_packets
	#args: udp_packets -> Array of UDP packets
	#Docs: This function will return a list of all the IPs that have a high packet rate
	burst_threshold = 100
	udp_flood = []
	for udp_p in udp_packets:
		if udp_p["count"] > 1:
			udp_rate = udp_p["count"]/(udp_p["End time"] - udp_p["Start Time"])
		else:
			udp_rate = udp_p["count"]
		if udp_rate > burst_threshold:
			#Packet is ICMP packet
			udp_flood.append(udp_p)
	return udp_flood
def calculate_avg_udp_packet_rate(udp_flood):
	#func: calculate_avg_udp_packet_rate
	#args: None
	#Docs: This function will calculate the average packet rate for the UDP DDoS attack.
	timestamps = []
	for p in udp_flood:
		timestamps.append(p["packet"].time)

	if timestamps:
		total_packets = len(udp_flood)
		#print(f"UDP size: {total_packets}")
		if(total_packets) > 1:
			first_time = timestamps[0]
			last_time = timestamps[-1]
			duration = last_time - first_time
			return total_packets / (duration)
		return 1

	return 0
def check_udp_flood():
	#func: udp_flood
	#args: None
	#Docs: This function will detect if there is a UDP flood attack in the pcap file.
	OUTPUT_REPORT = {"UDP FLOOD DETECTED": False}
	udp_flood = []
	udp_packets, target_ip  = calculate_udp_from_ips()
	
	#Get burst rate of UDP traffic
	udp_flood = get_udp_flood_packets(udp_packets)

	#Make report
	if len(udp_flood) > 0:
		#UDP packets have exceed UDP flood
		OUTPUT_REPORT["UDP FLOOD DETECTED"] = True
		OUTPUT_REPORT["packets"] = udp_flood
		OUTPUT_REPORT["target ip"] = target_ip
		OUTPUT_REPORT["avg packet rate"] = calculate_avg_udp_packet_rate(udp_flood)



	return OUTPUT_REPORT

def expand(x):
	#func: expand
	#args: x -> x is the packet
	#Docs: This function will return the content of the packet
	#This function was from: https://stackoverflow.com/questions/13549294/get-all-the-layers-in-a-packet
	yield x.name
	while x.payload:
		x = x.payload
		yield x.name
def read_packets(packets):
	#funcs: read_packets
	#args: packets -> a list of all packets
	#Docs: This function will read all the packets and group them into there type
	#-----------------------------------
	#CHANGE THIS WHOLE FUNCTION!!!!!!!!!!
	global packet_number
	packet_number = len(packets)
	for p in packets:
		packet_content = list(expand(p))
		#print(packet_content)
		#check the types of packets
		if p.haslayer(DNS):
			#dns
			print(packet_content)
			dns_list.append(p)
		elif p.haslayer(UDP) and (p[UDP].dport == 443 or p[UDP].sport == 443):
			#quic
			print(packet_content)
			quic_list.append(p)
		elif p.haslayer(UDP) and (p[UDP].sport == 5353 or p[UDP].dport == 5353): #and p.haslayer(DNS):
			#MDNS
			mdns_list.append(p)
		elif p.haslayer(ARP):
			#arp
			arp_list.append(p)
		elif p.haslayer(TCP) and (p[TCP].sport == 80 or p[TCP].dport == 80):
			#http
			http_list.append(p)
		elif p.haslayer(TCP) and p.haslayer(IP):
			#tcp IPv4
			tcp_list.append(p)
		elif p.haslayer(IP) and "ICMP" in packet_content:
			#ICMP packet <-(p.haslayer(ICMP) is not working)->
			#ERROR is very weird could not understand why it did not work
			icmp_list.append(p)
		elif "UDP" in packet_content:	
			#udp
			udp_list.append(p)
		else:
			#other packets
			if 'TCP' not in packet_content:
				print(packet_content)
			other_packets.append(p)
	print(f"MDNS list: {len(mdns_list)}")
def plot_network_traffic():
	#func: plot_network_traffic
	#args: None
	#Docs: This function will plot all the network traffic on a pie chart
	labels = []
	sizes = []
	if len(tcp_list) > 0:
		labels.append("TCP")
		sizes.append(len(tcp_list))
	if len(quic_list) > 0:
		labels.append("QUIC")
		sizes.append(len(quic_list))
	if len(icmp_list) > 0:
		labels.append("ICMP")
		sizes.append(len(icmp_list))
	if len(arp_list) > 0:
		labels.append("ARP")
		sizes.append(len(arp_list))
	if len(dns_list) > 0:
		labels.append("DNS")
		sizes.append(len(dns_list))
	if len(udp_list) > 0:
		labels.append("UDP")
		sizes.append(len(udp_list))
	if len(mdns_list) > 0:
		labels.append("MDNS")
		sizes.append(len(mdns_list))
	if len(http_list) > 0:
		labels.append("HTTP")
		sizes.append(len(http_list))
	if len(other_packets) > 0:
		labels.append("other")
		sizes.append(len(other_packets))

	#Plot piechart
	explode = [0.05] * len(labels)
	plt.pie(sizes, labels=labels, colors=COLORS[:len(labels)], autopct="%1.1f%%", startangle=140,explode=explode, wedgeprops={'edgecolor': 'black'})
	plt.title(f"Total network traffic: {packet_number}")
	plt.axis("equal")
	plt.savefig("pie_chart.png")
def addTitle(doc):
	#func: addTitle
	#args: doc -> This is the document object for the PDF file.
	#Docs: This function is a helper function for 'createReport()'.
	#This function will add a title to the pdf document.
	doc.append(Spacer(1,20))
	doc.append(Paragraph('PCAP Analysis report',ParagraphStyle(name="Doc",fontFamily="Helvetica",fontSize=36,alignment=TA_CENTER)))
	doc.append(Spacer(1,20))
def get_packet_rate(packet_list):
	#func: get_packet_rate
	#args: packet_list -> 
	#Docs: This function will return a packet rate for a list of packets
	timestamps = []
	for p in packet_list:
		timestamps.append(p.time)
	if timestamps:
		if len(timestamps) == 1:
			return len(packet_list)
		first_time = timestamps[0]
		end_time = timestamps[-1]
		packet_rate = len(packet_list) / (end_time- first_time)
		return packet_rate
def get_avg_packet_size(packet_list):
	#func: get_avg_packet_size
	#args: packet_list -> 
	#Docs: This function return the avg size of the packets in a list
	total_size = 0
	for p in packet_list:
		total_size = total_size + len(p)

	return total_size /len(packet_list)

def packet_details():
	#func: packet_details
	#args: paragraph_style -> The style object of the paragraph
	#Docs: This function is a helper function for 'createReport'
	#This function will add all the details about the packet into the PDF document
	text = ""
	styles = getSampleStyleSheet()
	paragraph_style = styles["Normal"]
	paragraph_style.wordWrap = "CJK"
	paragraph_style.spaceBefore = 15  # Space before the paragraph
	paragraph_style.spaceAfter = 5   # Space after the paragraph
	paragraph_style.leftIndent = 40   # Indentation from the left
	paragraph_style.rightIndent = 10  # Optional: Indentation from the right
	paragraph_style.leading = 10
	i = 0 
	if len(tcp_list) > 0:
		tcp_rate = get_packet_rate(tcp_list)
		avg_size = get_avg_packet_size(tcp_list)
		text = text + f"""<font color="{COLORS[i]}">TCP</font>: {len(tcp_list)} TCP packets. AVG packet size of: {avg_size:.2f} <br/><br/> packet rate: {tcp_rate:.2f}<br/><br/>"""
		i = i +1
	if len(quic_list) > 0:
		quic_rate = get_packet_rate(quic_list)
		avg_size = get_avg_packet_size(quic_list)
		text = text + f"""<font color="{COLORS[i]}">QUIC</font>: {len(quic_list)} QUIC packets. AVG packet size of: {avg_size:.2f} <br/><br/> packet rate: {quic_rate:.2f}<br/><br/>"""
		i = i +1
	if len(icmp_list) > 0:
		icmp_rate = get_packet_rate(icmp_list)
		avg_size = get_avg_packet_size(icmp_list)
		text = text + f"""<font color="{COLORS[i]}">ICMP</font>: {len(icmp_list)} ICMP packets. AVG packet size of: {avg_size:.2f} <br/><br/> packet rate: {icmp_rate:.2f}<br/><br/>"""
		i = i +1
	if len(arp_list) > 0:
		arp_rate = get_packet_rate(arp_list)
		avg_size = get_avg_packet_size(arp_list)
		text = text + f"""<font color="{COLORS[i]}">ARP</font>: {len(arp_list)} ARP packets. AVG packet size of: {avg_size:.2f} <br/><br/> packet rate: {arp_rate:.2f}<br/><br/>"""
		i = i +1
	if len(dns_list) > 0:
		dns_rate = get_packet_rate(dns_list)
		avg_size = get_avg_packet_size(dns_list)
		text = text + f"""<font color="{COLORS[i]}">DNS</font>: {len(dns_list)} DNS packets. AVG packet size of: {avg_size:.2f} <br/><br/> packet rate: {dns_rate:.2f}<br/><br/>"""
		i = i +1
	if len(udp_list) > 0:
		udp_rate = get_packet_rate(udp_list)
		avg_size = get_avg_packet_size(udp_list)
		text = text + f"""<font color="{COLORS[i]}">UDP</font>: {len(udp_list)} UDP packets. AVG packet size of: {avg_size:.2f}<br/><br/> packet rate: {udp_rate:.2f}<br/><br/>"""
		i = i +1
	if len(mdns_list) > 0:
		mdns_rate = get_packet_rate(mdns_list)
		avg_size = get_avg_packet_size(mdns_list)
		text = text + f"""<font color="{COLORS[i]}">MDNS</font>: {len(mdns_list)} MDNS packets. AVG packet size of: {avg_size:.2f} <br/><br/> packet rate: {mdns_rate:.2f}<br/><br/>"""
		i = i +1
	if len(http_list) > 0:
		http_rate = get_packet_rate(http_list)
		avg_size = get_avg_packet_size(http_list)
		text = text + f"""<font color="{COLORS[i]}">HTTP</font>: {len(http_list)} MDNS packets. AVG packet size of: {avg_size:.2f} <br/><br/> packet rate: {http_rate:.2f}<br/><br/>"""
		i = i + 1
	if len(other_packets) > 0:
		other_rate = get_packet_rate(other_packets)
		avg_size = get_avg_packet_size(other_packets)
		text = text + f"""<font color="{COLORS[i]}">Other</font>: {len(other_packets)} Other packets. AVG packet size of: {avg_size:.2f} <br/><br/> packet rate: {other_rate:.2f}<br/><br/>"""
		i = i +1
	body = Paragraph(text,paragraph_style)

	return body
def create_ip_table(list_ips):
	#func: create_ip_table
	#args: list_ips - > List of IP addresses
	#Docs: This function will create the table of IPS. 
	#This function will return a table to be added to the document
	#Will sort the ips from highest number send to lowest number sent
	#Output grid of inforation of IP'S
	data_grid = [["IP", "Total Packets Sent", "Total Bytes Sent", "Packet Rate"]]
	#Sort the list of IPs but the highest packets send to the lowest 
	sorted_ips = sorted(list_ips, key=lambda x: x['count'], reverse=True)
	for d in sorted_ips:
		if isinstance(d['packet'], TCP_packet):
			attacker_ip = d['packet'].getSrc()
		else:
			attacker_ip = d['packet'][IP].src
		attack_count = d['count']
		attacker_byte_size = d["total bytes"]
		if d["count"] > 1:
			packet_rate = round(d['count'] / (d["End time"] - d["Start Time"]),2)
		else:
			packet_rate = d["count"]
		data_grid.append([attacker_ip,attack_count,attacker_byte_size,packet_rate])
	table = Table(data_grid, colWidths=[150, 150, 150, 150])  # Adjust widths

	# Apply Table Style
	table.setStyle(TableStyle([
		("GRID", (0, 0), (-1, -1), 1, colors.black),  # Black grid lines
		("BACKGROUND", (0, 0), (-1, 0), colors.grey),  # Header background color
		("TEXTCOLOR", (0, 0), (-1, 0), colors.white),  # Header text color
		("ALIGN", (0, 0), (-1, -1), "CENTER"),  # Center align text
		("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),  # Bold header font
		("BOTTOMPADDING", (0, 0), (-1, 0), 8),  # Padding for header
		("TOPPADDING", (0, 0), (-1, -1), 5),  # Padding for all cells
		]))
	return table
def generate_icmp_flood_text(report,paragraph_style):
	#func: generate_icmp_flood_text
	#args: report-> ,paragraph_style -> 
	#Docs: 
	elements = []
	if(report["ICMP FLOOD DETECTED"] == True):
		packet_list = report["packets"]
		target_ips = report["target ip"]
		avg_packet_rate = round(report["avg packet rate"],2)
		text = f"<b>ICMP Flood</b>: <font color=red>[DDoS ALERT]</font> High volume of suspicious traffic detected! <br/><br/> - Target IP: {target_ips} <br/><br/> - Average Packet Rate: {avg_packet_rate} <br/><br/> - Below is a list of IP addresses suspected to be the source of the attack."
		icmp_flood_text = Paragraph(text, paragraph_style)
		elements.append(icmp_flood_text)
		#Add table
		table = create_ip_table(packet_list)
		elements.append(table)

	else:
		text = f"<b>ICMP Flood</b>: No ICMP flood attack detected. ICMP traffic from PCAP file seems normal."
		icmp_flood_text = Paragraph(text, paragraph_style)
		elements.append(icmp_flood_text)
	return elements
def generate_syn_flood_text(report,paragraph_style):
	#func: syn_flood_text
	#args: report-> 
	#Docs: This function will generate the result text for the SYN FLOOD on the PDF
	elements = []
	if(report["SYN FLOOD DETECTED"] == True):
		#SYN flood 
		packet_list = report["packets"]
		num_attacker_ips = len(packet_list)
		target_ips = report["target ip"]
		target_port = report["target port"]
		packet_rate = report["packet rate"]
		flood_percentage = report["SYN Flood percentage"] * 100
		text = f"<b>TCP SYN Flood</b>: <font color=red>[DDoS ALERT]</font> High volume of suspicious traffic detected! <br/><br/> - Target IP: {target_ips} <br/><br/> - Number of Attacker IPs: {num_attacker_ips} <br/><br/> - Target Port: {target_port} <br/><br/> - Packet Rate: {packet_rate:.2f} packets/sec <br/><br/> - {flood_percentage:.2f}% of the TCP traffic is detected as TCP SYN Flood attack <br/><br/> - Below is a list of IP addresses suspected to be the source of the attack."

		syn_flood_text = Paragraph(text, paragraph_style)
		elements.append(syn_flood_text)

		#add table
		#Output grid of inforation of IP'S
		table = create_ip_table(packet_list)

		elements.append(table)  # Add table to elements

	else:
		#No, SYN flood
		text = "<b>TCP SYN Flood</b>: No TCP SYN flood attack detected. TCP traffic from PCAP file seems normal."
		syn_flood_text = Paragraph(text, paragraph_style)
		elements.append(syn_flood_text)
	return elements
def generate_udp_flood_text(report,paragraph_style):
	#func: generate_udp_flood_text
	#args: report -> . paragraph_style -> 
	#Docs: This function will generate the result text for the UDP flood on the PDF
	elements = []
	if(report["UDP FLOOD DETECTED"] == True):
		target_ips = report["target ip"]
		packet_list = report["packets"]
		avg_packet_rate = round(report["avg packet rate"],2)
		num_attacker_ips = len(packet_list)
		text = f"<b>UDP Flood</b>: <font color=red>[DDoS ALERT]</font> High volume of suspicious traffic detected! <br/><br/> - Target IP: {target_ips} <br/><br/> - Number of Attacker IPs: {num_attacker_ips} <br/><br/> - Average Packet Rate: {avg_packet_rate} <br/><br/> - Below is a list of IP addresses suspected to be the source of the attack."
		udp_flood_text = Paragraph(text, paragraph_style)
		elements.append(udp_flood_text)

		#Create IP table
		table = create_ip_table(packet_list)
		elements.append(table)
	else:
		text = f"<b>UDP Flood</b>: No UDP flood attack detected. UDP traffic from PCAP file seems normal."
		udp_flood_text = Paragraph(text, paragraph_style)
		elements.append(udp_flood_text)
	return elements
def generate_http_get_flood_text(report,paragraph_style):
	#func: generate_http_get_flood_text
	#args: report -> ,paragraph_style -> 
	#Docs: This function will generate the result text for the HTTP-GET fllod on the pdf.
	elements = []
	if(report["HTTP-GET FLOOD DETECTED"] == True):
		target_ips = report["target ip"]
		packet_list = report["packets"]
		avg_packet_rate = round(report["avg packet rate"],2)
		num_attacker_ips = len(packet_list)
		text = f"<b>HTTP-GET Flood</b>: <font color=red>[DDoS ALERT]</font> High volume of suspicious traffic detected! <br/><br/> - Target IP: {target_ips} <br/><br/> - Number of Attacker IPs: {num_attacker_ips} <br/><br/> - Average Packet Rate: {avg_packet_rate} <br/><br/> - Below is a list of IP addresses suspected to be the source of the attack."
		udp_flood_text = Paragraph(text, paragraph_style)
		elements.append(udp_flood_text)
	else:
		text = f"<b>HTTP-GET Flood</b>: No HTTP-GET flood attack detected. HTTP-GET traffic from PCAP file seems normal."
		http_flood_text = Paragraph(text, paragraph_style)
		elements.append(http_flood_text)

	return elements
def generate_no_ddos_text():
	#func: generate_no_ddos_text
	#args: None
	#Docs: This function will report if a there are no DDoS attacks detected in the PCAP file.
	text = "After thoroughly analyzing the pcap file, we have found no evidence of suspicious traffic indicative of a Distributed Denial-of-Service (DDoS) attack. The network traffic patterns appear consistent with normal activity, with no abnormal spikes in packet rates, unusual connection attempts, or high-volume requests targeting a specific host. Additionally, there are no signs of SYN floods, UDP floods and ICMP floods that would typically characterize a DDoS event. Based on this assessment, we conclude that the observed traffic does not exhibit malicious intent or behavior associated with a coordinated attack."
	styles = getSampleStyleSheet()
	paragraph_style = styles["Normal"]
	paragraph_style.wordWrap = "CJK"
	paragraph_style.spaceBefore = 20  # Space before the paragraph
	paragraph_style.spaceAfter = 20   # Space after the paragraph
	paragraph_style.leftIndent = 50   # Indentation from the left
	paragraph_style.rightIndent = 10  # Optional: Indentation from the right
	paragraph_style.leading = 14
	no_ddos_text = Paragraph(text, paragraph_style)
	return no_ddos_text

def report_conclusion(tcp,udp,icmp,http=False):
	#func: report_conclusion
	#args:
	#Docs: This function will give a conclusion of the report. This function will be called when at least one DDoS attack is detected.
	styles = getSampleStyleSheet()
	bullet_point_style = ParagraphStyle(
		name="BulletPoint",
		parent=styles["Normal"],
		leftIndent=1,  # Adjust indentation for bullets
		spaceAfter=1,    # Add spacing after each bullet point
	)

	paragraph_style = styles["Normal"]
	paragraph_style.wordWrap = "CJK"
	paragraph_style.spaceBefore = 20  # Space before the paragraph
	paragraph_style.spaceAfter = 20   # Space after the paragraph
	paragraph_style.leftIndent = 1   # Indentation from the left
	paragraph_style.rightIndent = 10  # Optional: Indentation from the right
	paragraph_style.leading = 14
	text = "Results of the PCAP analysis:<br/><br/><ul>"
	bullet_points = []

	if tcp["SYN FLOOD DETECTED"] == False:
		syn_per = tcp["SYN Flood percentage"] * 100
		bullet_points.append(
			f"No evidence of a SYN flood attack has been detected. "
			f"Only {syn_per:.2f}% of TCP handshakes remain incomplete, which is within the expected threshold for normal network fluctuations. "
			f"Additionally, there are no abnormal spikes in SYN packet rates or signs of bursty traffic behavior that would indicate a volumetric attack.")
	else:
		bullet_points.append("SYN flood has been detected.")
	if udp["UDP FLOOD DETECTED"] == False:
		bullet_points.append("No evidence of a UDP flood attack has been detected.")
	else:
		bullet_points.append("UDP flood has been detected.")
	if icmp["ICMP FLOOD DETECTED"] == False:
		bullet_points.append("No evidence of an ICMP flood attack has been detected.")
	else:
		bullet_points.append("ICMP flood has been detected.")
	if http["HTTP-GET FLOOD DETECTED"] == False:
		bullet_points.append("No evidence of an HTTP-GET flood attack has been detected.")
	else:
		bullet_points.append("HTTP-GET flood has been detected.")

    # Create a list with bullet formatting
	bullet_list = ListFlowable(
		[ListItem(Paragraph(point, bullet_point_style)) for point in bullet_points],
		bulletType="bullet",  # Uses standard bullet points
		)
	#add to paragraph
	 
	conclusion = Paragraph(text,paragraph_style)
	return [conclusion,bullet_list]

def createReport(pcap_file,syn_flood_report,udp_flood_report,icmp_flood_report,http_get_fllod_report):
	#func: createReport
	#args:
	#Docs: This function will create a PDF report for the analysis of the PCAP file.
	document = []
	addTitle(document)

	#Add Text
	text = f"This report analyzes the PCAP file: {pcap_file}. It will determine whether a DDoS attack is detected. Some types of attacks we will search for include: SYN flooding, UDP flooding, ICMP flooding, and HTTP-GET flooding."
	styles = getSampleStyleSheet()
	paragraph_style = styles["Normal"]
	paragraph_style.wordWrap = "CJK"
	paragraph_style.spaceBefore = 20  # Space before the paragraph
	paragraph_style.spaceAfter = 20   # Space after the paragraph
	paragraph_style.leftIndent = 50   # Indentation from the left
	paragraph_style.rightIndent = 10  # Optional: Indentation from the right
	paragraph_style.leading = 14 
	intro_par = Paragraph(text,paragraph_style)
	document.append(intro_par)
	

	#create plot data
	plot_network_traffic()

	#Add plot to PDF
	graph = Image("pie_chart.png",width=400,height=300)
	#Output report of packets
	

	body = packet_details()
	#body_table = Table([body],colWidths=[300])
	#document.append(body_table)
	styles = getSampleStyleSheet()
	paragraph_style = styles["Normal"]
	paragraph_style.wordWrap = "CJK"
	paragraph_style.spaceBefore = 20  # Space before the paragraph
	paragraph_style.spaceAfter = 20   # Space after the paragraph
	paragraph_style.leftIndent = 50   # Indentation from the left
	paragraph_style.rightIndent = 10  # Optional: Indentation from the right
	paragraph_style.leading = 5
	separator = HRFlowable(width="100%", thickness=1, color="black")
	#No DDoS detected

	table = Table([[graph, body]], colWidths=[300, 400]) 

	table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),  # Align text & graph to top
        ("WORDWRAP", (1, 0), (1, -1), "CJK"),  # Enable text wrapping
          # Debugging grid (optional)
    ]))

	document.append(table)  # Graph + Text Table
	document.append(Spacer(1, 10))	
	document.append(separator)  # Horizontal line separator
	if syn_flood_report["SYN FLOOD DETECTED"] == False and udp_flood_report["UDP FLOOD DETECTED"] == False and icmp_flood_report["ICMP FLOOD DETECTED"] == False:
		no_ddos_text = generate_no_ddos_text()
		document.append(Spacer(1, 10))
		document.append(no_ddos_text)
	else:
		if syn_flood_report["SYN FLOOD DETECTED"] == True:
			syn_flood_text = generate_syn_flood_text(syn_flood_report,paragraph_style)
			document.append(Spacer(1, 10))
			document.extend(syn_flood_text)
		if udp_flood_report["UDP FLOOD DETECTED"] == True:
			udp_flood_text = generate_udp_flood_text(udp_flood_report,paragraph_style)
			document.append(Spacer(1, 10))
			document.extend(udp_flood_text)
		if icmp_flood_report["ICMP FLOOD DETECTED"] == True:
			icmp_flood_text = generate_icmp_flood_text(icmp_flood_report,paragraph_style)
			document.append(Spacer(1, 10))
			document.extend(icmp_flood_text)
		if http_get_fllod_report["HTTP-GET FLOOD DETECTED"] == True:
			http_flood_text = generate_http_get_flood_text()
			document.append(Spacer(1, 10))
			document.extend(http_flood_text)
	#Add Conclusion
	conclusion = report_conclusion(syn_flood_report,udp_flood_report,icmp_flood_report,http_get_fllod_report)
	document.extend(conclusion)



	SimpleDocTemplate(FILE_NAME,pagesize=letter,rightMargin=10,leftMargin=10,topMargin=12,bottomMargin=6).build(document)
def analyze_network_traffic():
	#func: analyze_network_traffic
	#args: None
	#Docs: This function will analyze all the network traffic.

	#SYN flood
	syn_flood_report = check_syn_flood()
	if syn_flood_report["SYN FLOOD DETECTED"] == True:
		print(Fore.RED+"SYN flood detected!")
		print(Fore.RED+"Details of the SYN flood will be included in the report")
	else:
		print(Fore.GREEN+"No SYN flood detected in PCAP")

	#UDP flood
	udp_flood_report = check_udp_flood()
	if udp_flood_report["UDP FLOOD DETECTED"] == True:
		print(Fore.RED+"UDP flood detected!")
		print(Fore.RED+"Details of the UDP flood will be included in the report")
	else:
		print(Fore.GREEN+"No UDP flood detected in PCAP")

	#ICMP flood
	icmp_flood_report = check_icmp_flood()
	if icmp_flood_report["ICMP FLOOD DETECTED"] == True:
		print(Fore.RED+"ICMP flood detected!")
		print(Fore.RED+"Details of the UDP flood will be included in the report")
	else:
		print(Fore.GREEN+"No ICMP flood detected in PCAP")

	#HTTP flood
	http_flood_report = check_http_get_flood()
	if http_flood_report["HTTP-GET FLOOD DETECTED"] == True:
		print(Fore.RED+"HTTP-GET flood detected!")
		print(Fore.RED+"Details of the HTTP-GET flood will be included in the report")
	else:
		print(Fore.GREEN+"No HTTP-GET flood detected in PCAP")

	return [syn_flood_report,udp_flood_report,icmp_flood_report,http_flood_report]

def parse_filename(filename):
	#func: parse_filename
	#args: filename - > The stirng that will be parsed
	#Docs: This function will make sure the filename is in the correct format.
	#Remove all '.' in the file name and any extensions
	if filename != "output-report.pdf":
		if "." in filename:
			#Check to see if its a pdf extension
			txt = filename.split(".")
			if txt[-1] != 'pdf':
				#File as incorrect extension
				filename = text[0] + ".pdf"
		else:
			filename = filename + ".pdf"
	return filename
def main():
	#func: main
	#args: None
	#Docs: This function will be the main function of the program
	global FILE_NAME
	parser = argparse.ArgumentParser(description="Read A PCAP file, gives summary of network content")
	parser.add_argument("pcap_file",help="Path to the PCAP file")
	parser.add_argument("-n","--filename",type=str,default="output-report.pdf",help="Set the name of the output PDF file")
	args = parser.parse_args()
	file = args.pcap_file
	temp_filname = args.filename

	FILE_NAME = parse_filename(temp_filname)

	#Read the pcap file
	try:

		packets = rdpcap(file)
		if len(packets) == 0:
			print(Fore.RED+"Error: PCAP file has no pacekts to read")
			sys.exit(1)
	except scapy.error.Scapy_Exception as e:
		print(Fore.RED+f"Error: Unable to read {file}")
		sys.exit(1)

	read_packets(packets)
	reports = analyze_network_traffic()
	#List of reports
	syn_flood_report = reports[0]
	udp_flood_report = reports[1]
	icmp_flood_report = reports[2]
	http_get_fllod_report = reports[3]


	createReport(args.pcap_file,syn_flood_report,udp_flood_report,icmp_flood_report,http_get_fllod_report)
	
		


main()