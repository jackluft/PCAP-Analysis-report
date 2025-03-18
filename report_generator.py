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
from scapy.all import IP
from packetObject import TCP_packet
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
COLORS = ["Red", "Blue", "Green", "Cyan", "Orange", "Purple", "Pink", "Yellow", "Teal"]
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
		avg_packet_rate = report["avg packet rate"]
		attack_duration = round(report["Attack Duration"],2)
		flood_percentage = report["SYN Flood percentage"] * 100
		text = f"<b>TCP SYN Flood</b>: <font color=red>[DDoS ALERT]</font> High volume of suspicious traffic detected! <br/><br/> - Target IP: {target_ips} <br/><br/> - Number of Attacker IPs: {num_attacker_ips} <br/><br/> - Target Port: {target_port} <br/><br/> - Packet Rate: {avg_packet_rate:.2f} packets/sec <br/><br/> - {flood_percentage:.2f}% of the TCP traffic is detected as TCP SYN Flood attack <br/><br/> - Attack Duration: {attack_duration}/secs  <br/><br/> - Below is a list of IP addresses suspected to be the source of the attack."

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
def generate_http_get_flood_text(report,paragraph_style):
	#func: generate_http_get_flood_text
	#args: report -> ,paragraph_style -> 
	#Docs: This function will generate the result text for the HTTP-GET fllod on the pdf.
	elements = []
	if(report["HTTP-GET FLOOD DETECTED"] == True):
		target_ips = report["target ip"]
		packet_list = report["packets"]
		attack_duration = report["Attack Duration"]
		avg_packet_rate = round(report["avg packet rate"],2)
		num_attacker_ips = len(packet_list)
		text = f"<b>HTTP-GET Flood</b>: <font color=red>[DDoS ALERT]</font> High volume of suspicious traffic detected! <br/><br/> - Target IP: {target_ips} <br/><br/> - Number of Attacker IPs: {num_attacker_ips} <br/><br/> - Average Packet Rate: {avg_packet_rate} <br/><br/> - Below is a list of IP addresses suspected to be the source of the attack."
		udp_flood_text = Paragraph(text, paragraph_style)
		elements.append(udp_flood_text)
		#Add table
		table = create_ip_table(packet_list)
		elements.append(table)
	else:
		text = f"<b>HTTP-GET Flood</b>: No HTTP-GET flood attack detected. HTTP-GET traffic from PCAP file seems normal."
		http_flood_text = Paragraph(text, paragraph_style)
		elements.append(http_flood_text)

	return elements
def generate_icmp_flood_text(report,paragraph_style):
	#func: generate_icmp_flood_text
	#args: report-> ,paragraph_style -> 
	#Docs: 
	elements = []
	if(report["ICMP FLOOD DETECTED"] == True):
		packet_list = report["packets"]
		target_ips = report["target ip"]
		avg_packet_rate = round(report["avg packet rate"],2)
		attack_duration = round(report["Attack Duration"],2)
		text = f"<b>ICMP Flood</b>: <font color=red>[DDoS ALERT]</font> High volume of suspicious traffic detected! <br/><br/> - Target IP: {target_ips} <br/><br/> - Average Packet Rate: {avg_packet_rate} <br/><br/> - Attack Duration: {attack_duration}/secs <br/><br/> - Below is a list of IP addresses suspected to be the source of the attack."
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
def generate_udp_flood_text(report,paragraph_style):
	#func: generate_udp_flood_text
	#args: report -> . paragraph_style -> 
	#Docs: This function will generate the result text for the UDP flood on the PDF
	elements = []
	if(report["UDP FLOOD DETECTED"] == True):
		target_ips = report["target ip"]
		packet_list = report["packets"]
		avg_packet_rate = round(report["avg packet rate"],2)
		attack_duration = round(report["Attack Duration"],2)
		num_attacker_ips = len(packet_list)
		text = f"<b>UDP Flood</b>: <font color=red>[DDoS ALERT]</font> High volume of suspicious traffic detected! <br/><br/> - Target IP: {target_ips} <br/><br/> - Number of Attacker IPs: {num_attacker_ips} <br/><br/> - Average Packet Rate: {avg_packet_rate} <br/><br/> - Attack Duration: {attack_duration}/secs <br/><br/> - Below is a list of IP addresses suspected to be the source of the attack."
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
def get_avg_packet_size(packet_list):
	#func: get_avg_packet_size
	#args: packet_list -> 
	#Docs: This function return the avg size of the packets in a list
	total_size = 0
	for p in packet_list:
		total_size = total_size + len(p)

	return total_size /len(packet_list)
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
		text = text + f"""<font color="{COLORS[i]}">HTTP</font>: {len(http_list)} HTTP packets. AVG packet size of: {avg_size:.2f} <br/><br/> packet rate: {http_rate:.2f}<br/><br/>"""
		i = i + 1
	if len(other_packets) > 0:
		other_rate = get_packet_rate(other_packets)
		avg_size = get_avg_packet_size(other_packets)
		text = text + f"""<font color="{COLORS[i]}">Other</font>: {len(other_packets)} Other packets. AVG packet size of: {avg_size:.2f} <br/><br/> packet rate: {other_rate:.2f}<br/><br/>"""
		i = i +1
	body = Paragraph(text,paragraph_style)

	return body
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
def createReport(pcap_file,filename,syn_flood_report,udp_flood_report,icmp_flood_report,http_get_fllod_report):
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
	if syn_flood_report["SYN FLOOD DETECTED"] == False and udp_flood_report["UDP FLOOD DETECTED"] == False and icmp_flood_report["ICMP FLOOD DETECTED"] == False and http_get_fllod_report["HTTP-GET FLOOD DETECTED"] == False:
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
			http_flood_text = generate_http_get_flood_text(http_get_fllod_report,paragraph_style)
			document.append(Spacer(1, 10))
			document.extend(http_flood_text)
	#Add Conclusion
	conclusion = report_conclusion(syn_flood_report,udp_flood_report,icmp_flood_report,http_get_fllod_report)
	document.extend(conclusion)

	SimpleDocTemplate(filename,pagesize=letter,rightMargin=10,leftMargin=10,topMargin=12,bottomMargin=6).build(document)
def set_packet_variables(packets):
	#func:
	#args:
	#Docs: This fucntion will set all the globol variables are all the packet lists
	global icmp_list
	global quic_list
	global arp_list
	global http_list
	global tcp_list
	global udp_list
	global dns_list
	global mdns_list
	global packet_number
	global other_packets

	icmp_list = packets["icmp_list"]
	quic_list = packets["quic_list"]
	arp_list = packets["arp_list"]
	http_list = packets["http_list"]
	tcp_list = packets["tcp_list"]
	udp_list = packets["udp_list"]
	dns_list = packets["dns_list"]
	mdns_list = packets["mdns_list"]
	packet_number = packets["packet_number"]
	other_packets = packets["other_packets"]

def PDFreport(pcap_file_name,packets,traffic_results):
	#func: report
	#args:
	#Docs: 
	syn_flood_report = packets[0]
	udp_flood_report = packets[1]
	icmp_flood_report = packets[2]
	http_get_fllod_report = packets[3]
	filename = traffic_results["FILE_NAME"]
	set_packet_variables(traffic_results)
	createReport(pcap_file_name,filename,syn_flood_report,udp_flood_report,icmp_flood_report,http_get_fllod_report)