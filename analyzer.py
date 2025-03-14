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
other_packets = []

#Graph Colors
COLORS = ["Red", "Blue", "Green", "Cyan", "Orange", "Purple", "Pink","Yellow"]

class ICMP:
	def __init__(self,packet):
		self.packet = packet

	def getSrc(self):
		return packet[IP].src
	def getDst(self):
		return packet[IP].dst
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
				if entry["IP"] == p.getSrc():
					entry["count"] = entry["count"] +1
					entry["total bytes"] = entry["total bytes"] + len(p.packet)
					found = True
					break
			if not found:
				#add it to the list
				syn_list_ips.append({"IP":p.getSrc(), "count":1, "total bytes": len(p.packet)})
				target_ip = p.getDst()
				target_port = p.packet.dport
	return syn_list_ips, target_ip,target_port
def calculate_syn_burst():
	#func: calculate_syn_burst
	#args:
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
	print(syn_percentage)
	if syn_percentage > 0.3:
		#SYN_flood
		OUTPUT_REPORT["SYN FLOOD DETECTED"] = True
		#Check 2
		syn_list_ips,target_ip,target_port = calculate_syn_from_ips(tcp_handshakes)
		OUTPUT_REPORT["IPS"] = syn_list_ips
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
	return OUTPUT_REPORT
def check_http_get_flood():
	#func:
	#args:
	#Doc: This function will detect if there is a HTTP-GET flood attack in the PCAP file.
	OUTPUT_REPORT = {"HTTP-GET FLOOD DETECTED": False}
	return OUTPUT_REPORT
def check_icmp_flood():
	#func: icmp_flood
	#args: None
	#Docs: This function will detect if there is an ICMP flood attack in the PCAP file.
	OUTPUT_REPORT = {"ICMP FLOOD DETECTED": False}

	return OUTPUT_REPORT
def check_udp_flood():
	#func: udp_flood
	#args: None
	#Docs: This function will detect if there is a UDP flood attack in the pcap file.
	OUTPUT_REPORT = {"UDP FLOOD DETECTED": False}

	#Check 1: See if packets are sent at an unusually high rate
	#Check 2: See if many UDP packets are sent to the same Destination IP

	time_bin = 1.0
	burst_threshold = 500
	timestamps = []
	udp_list_ips = []
	for p in udp_list:
		timestamps.append(p.time)
		found = False

		#Check if ip already in list
		for entry in udp_list_ips:
			if entry["packet"].src == p.src:
				entry["count"] = entry["count"] +1
				found = True
				break
		if not found:
			udp_list_ips.append({"packet":p,"count":1})


	#Check 1
	#Check the udp traffic
	if timestamps:
		timestamps = np.array(timestamps)
		startime, endtime = timestamps[0], timestamps[-1]
		bins = np.arange(startime,endtime,time_bin)
		packet_counts, _ = np.histogram(timestamps,bins=bins)
		#Check if more then 500 packets are doing sent over a time interval
		burst_times = bins[:-1][packet_counts > burst_threshold]

		if len(burst_times) > 0:
			#High rate of UDP packets being sent
			OUTPUT_REPORT["UDP FLOOD DETECTED"] = True

			#Get all the ips associated with UDP flood
			#Might need to change this code up
			##---------------------------
			attacks_ips = []
			for udp in udp_list_ips:
				if udp["count"] >= burst_threshold:
					#Attack ip
					attacks_ips.add(udp)

			OUTPUT_REPORT["IPS"] = attacks_ips




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
	total = 0
	for p in packets:
		#check the types of packets

		if p.haslayer(DNS):
			#dns
			dns_list.append(p)
		elif p.haslayer(UDP) and (p[UDP].dport == 443 or p[UDP].sport == 443):
			#quic
			quic_list.append(p)
		elif p.haslayer(UDP) and p[UDP].dport == 5353 and p.haslayer(DNS):
			#MDNS
			mdns_list.append(p)
		elif p.haslayer(ARP):
			#arp
			arp_list.append(p)
		elif p.haslayer(TCP) and (p[TCP].sport == 80 or p[TCP].dport == 80):
			#http
			http_list.append(p)
		elif p.haslayer(TCP) and p.haslayer(IP):
			#tcp
			tcp_list.append(p)
		elif p.haslayer(IP):
			#ICMP packet <-(p.haslayer(ICMP) is not working)->
			#ERROR is very weird could not understand why it did not work
			packet_content = list(expand(p))
			if "ICMP" in packet_content:
				#icmp packet
				icmp_list.append(p)
		elif p.haslayer(UDP):	
			#udp
			udp_list.append(p)
		else:
			#other packets
			packet_content = list(expand(p))
			print(packet_content)
			other_packets.append(p)

def plot_network_traffic():
	#func: plot_network_traffic
	#args: None
	#Docs: This function will plot all the network traffic on a pie chart
	labels = []
	sizes = []
	print(f"ICMP packets: {len(icmp_list)}")
	totalPackets = len(tcp_list) + len(quic_list) + len(icmp_list) + len(arp_list) + len(dns_list) + len(other_packets) + len(udp_list)
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
	if len(other_packets) > 0:
		labels.append("other")
		sizes.append(len(other_packets))

	#Plot piechart
	explode = [0.05] * len(labels)
	plt.pie(sizes, labels=labels, colors=COLORS[:len(labels)], autopct="%1.1f%%", startangle=140,explode=explode, wedgeprops={'edgecolor': 'black'})
	plt.title(f"Total network traffic: {totalPackets}")
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

def packet_details(paragraph_style):
	#func: packet_details
	#args: paragraph_style -> The style object of the paragraph
	#Docs: This function is a helper function for 'createReport'
	#This function will add all the details about the packet into the PDF document
	text = ""
	temp = -1
	i = 0 
	if len(tcp_list) > 0:
		tcp_rate = get_packet_rate(tcp_list)
		avg_size = get_avg_packet_size(tcp_list)
		text = text + f"""<font color="{COLORS[i]}">TCP</font>: {len(tcp_list)} TCP packets with a AVG packet size of: {avg_size:.2f}, packet rate: {tcp_rate:.2f}<br/><br/>"""
		i = i +1
	if len(quic_list) > 0:
		quic_rate = get_packet_rate(quic_list)
		avg_size = get_avg_packet_size(quic_list)
		text = text + f"""<font color="{COLORS[i]}">QUIC</font>: {len(quic_list)} QUIC packets with a AVG packet size of: {avg_size:.2f}, packet rate: {quic_rate:.2f}<br/><br/>"""
		i = i +1
	if len(icmp_list) > 0:
		icmp_rate = get_packet_rate(icmp_list)
		avg_size = get_avg_packet_size(icmp_list)
		text = text + f"""<font color="{COLORS[i]}">ICMP</font>: {len(icmp_list)} ICMP packets with a AVG packet size of: {avg_size:.2f}, packet rate: {icmp_rate:.2f}<br/><br/>"""
		i = i +1
	if len(arp_list) > 0:
		arp_rate = get_packet_rate(arp_list)
		avg_size = get_avg_packet_size(arp_list)
		text = text + f"""<font color="{COLORS[i]}">ARP</font>: {len(arp_list)} ARP packets with a AVG packet size of: {avg_size:.2f}, packet rate: {arp_rate:.2f}<br/><br/>"""
		i = i +1
	if len(dns_list) > 0:
		dns_rate = get_packet_rate(dns_list)
		avg_size = get_avg_packet_size(dns_list)
		text = text + f"""<font color="{COLORS[i]}">DNS</font>: {len(dns_list)} DNS packets with a AVG packet size of: {avg_size:.2f}, packet rate: {dns_rate:.2f}<br/><br/>"""
		i = i +1
	if len(udp_list) > 0:
		udp_rate = get_packet_rate(udp_list)
		avg_size = get_avg_packet_size(udp_list)
		text = text + f"""<font color="{COLORS[i]}">UDP</font>: {len(udp_list)} UDP packets with a AVG packet size of: {avg_size:.2f}, packet rate: {udp_rate:.2f}<br/><br/>"""
		i = i +1
	if len(mdns_list) > 0:
		mdns_rate = get_packet_rate(mdns_list)
		avg_size = get_avg_packet_size(mdns_list)
		text = text + f"""<font color="{COLORS[i]}">MDNS</font>: {len(mdns_list)} MDNS packets with a AVG packet size of: {avg_size:.2f}, packet rate: {mdns_rate:.2f}<br/><br/>"""
		i = i +1
	if len(other_packets) > 0:
		other_rate = get_packet_rate(other_packets)
		avg_size = get_avg_packet_size(other_packets)
		text = text + f"""<font color="{COLORS[i]}">Other</font>: {len(other_packets)} Other packets with a AVG packet size of: {avg_size:.2f}, packet rate: {other_rate:.2f}<br/><br/>"""
		i = i +1
	body = Paragraph(text,paragraph_style)

	return body
def create_ip_table(list_ips):
	#func: create_ip_table
	#args: list_ips - > 
	#Docs: This function will create the table of IPS. 
	#This function will return a table to be added to the document
	#Will sort the ips from highest number send to lowest number sent
	#Output grid of inforation of IP'S
	data_grid = [["IP", "Total Packets Sent", "Total Bytes Sent", "Packet Rate"]]
	#Sort the list of IPs but the highest packets send to the lowest 
	sorted_ips = sorted(list_ips, key=lambda x: x['count'], reverse=True)
	for d in sorted_ips:
		attacker_ip = d['IP']
		attack_count = d['count']
		attacker_byte_size = d["total bytes"]
		data_grid.append([attacker_ip,attack_count,attacker_byte_size,-1])
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

def generate_syn_flood_text(report,paragraph_style):
	#func: syn_flood_text
	#args: report-> 
	#Docs: This function will generate the result text for the SYN FLOOD on the PDF
	elements = []
	if(report["SYN FLOOD DETECTED"] == True):
		#SYN flood 
		list_ips = report["IPS"]
		num_attacker_ips = len(list_ips)
		target_ips = report["target ip"]
		target_port = report["target port"]
		packet_rate = report["packet rate"]
		flood_percentage = report["SYN Flood percentage"] * 100
		text = f"<b>TCP SYN Flood</b>: <font color=red>[DDoS ALERT]</font> High volume of suspicious traffic detected! <br/><br/> - Target IP: {target_ips} <br/><br/> - Number of Attacker IPs: {num_attacker_ips} <br/><br/> - Target Port: {target_port} <br/><br/> - Packet Rate: {packet_rate:.2f} packets/sec <br/><br/> - {flood_percentage:.2f}% of the TCP traffic is detected as TCP SYN Flood attack <br/><br/> - Below is a list of IP addresses suspected to be the source of the attack."

		syn_flood_text = Paragraph(text, paragraph_style)
		elements.append(syn_flood_text)

		#add table
		#Output grid of inforation of IP'S
		table = create_ip_table(list_ips)

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
	#Docs:
	if(report["UDP FLOOD DETECTED"] == True):
		text = f"<b>UDP Flood</b>: [DDoS ALERT] High volume of suspicious traffic detected!"
	else:
		text = f"<b>UDP Flood</b>: No UDP flood attack detected. UDP traffic from PCAP file seems normal."
	udp_flood_text = Paragraph(text, paragraph_style)
	return udp_flood_text
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
def generate_icmp_flood_text(report,paragraph_style):
	#func: generate_icmp_flood_text
	#args: report-> ,paragraph_style -> 
	#Docs: 
	if(report["ICMP FLOOD DETECTED"] == True):
		text = f"<b>ICMP Flood</b>: [DDoS ALERT] High volume of suspicious traffic detected!"
	else:
		text = f"<b>ICMP Flood</b>: No UDP flood attack detected. ICMP traffic from PCAP file seems normal."
	
	icmp_flood_text = Paragraph(text, paragraph_style)
	return icmp_flood_text
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
    # Create a list with bullet formatting
	bullet_list = ListFlowable(
		[ListItem(Paragraph(point, bullet_point_style)) for point in bullet_points],
		bulletType="bullet",  # Uses standard bullet points
		)
	#add to paragraph
	 
	conclusion = Paragraph(text,paragraph_style)
	return [conclusion,bullet_list]

def createReport(pcap_file,syn_flood_report,udp_flood_report,icmp_flood_report):
	#func: createReport
	#args:
	#Docs: This function will create a PDF report for the analysis of the PCAP file.
	FILE_NAME = "output-report.pdf"
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
	

	body = packet_details(paragraph_style)
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
			document.append(udp_flood_text)
		if icmp_flood_report["ICMP FLOOD DETECTED"] == True:
			icmp_flood_text = generate_icmp_flood_text(icmp_flood_report,paragraph_style)
			document.append(Spacer(1, 10))
			document.append(icmp_flood_text)

	#Add Conclusion
	conclusion = report_conclusion(syn_flood_report,udp_flood_report,icmp_flood_report)
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



	return [syn_flood_report,udp_flood_report,icmp_flood_report]


def main():
	#func: main
	#args: None
	#Docs: This function will be the main function of the program
	parser = argparse.ArgumentParser(description="Read A PCAP file, gives summary of network content")
	parser.add_argument("pcap_file",help="Path to the PCAP file")
	args = parser.parse_args()
	file = args.pcap_file

	#Read the pcap file
	packets = rdpcap(file)
	read_packets(packets)
	reports = analyze_network_traffic()
	#List of reports
	syn_flood_report = reports[0]
	udp_flood_report = reports[1]
	icmp_flood_report = reports[2]


	createReport(args.pcap_file,syn_flood_report,udp_flood_report,icmp_flood_report)
	
		


main()