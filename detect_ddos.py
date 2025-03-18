from colorama import Fore
from scapy.all import TCP,IPv6,IP,ICMP
from packetObject import TCP_packet
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
def calculate_avg_packet_rate(packets):
	#func: calculate_avg_udp_packet_rate
	#args: None
	#Docs: This function will calculate the average packet rate for the UDP DDoS attack.

	total_packets = sum(data["count"] for data in packets)
	start_time = min(data["Start Time"] for data in packets)
	end_time = max(data["End time"] for data in packets)
	duration = end_time - start_time

	if(duration != 0):
		return total_packets / duration

	return 1
def group_packts_by_ip(packets):
	#func: group_packts_by_ip
	#args: None
	#Docs: This function will return a list of ips that have sent multiple packets.
	#Will return the format: {"packet":p, "count":1, "total bytes": len(p), "Start Time": packet_time, "End time": packet_time}
	ip_group = []
	target_ip = None
	#{"IP": p, "count": x}
	for p in packets:
		found = False
		#Check if ip already in list
		for entry in ip_group:
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
			ip_group.append({"packet":p, "count":1, "total bytes": len(p), "Start Time": packet_time, "End time": packet_time})
			if p.haslayer(IPv6):
				target_ip = p[IPv6].dst
			else:
				target_ip = p[IP].dst
	return ip_group, target_ip
def calculate_Attack_Duration(flood_packets):
	#func: calculate_Attack_Duration
	#args: flood_packets -> List of all 
	#Docs: This function will calculate the Attack Duration (How long did the attack last for)
	if len(flood_packets) > 0:
		min_start_time = min(d["Start Time"] for d in flood_packets)
		max_end_time = max(d["End time"] for d in flood_packets)
		attack_duration = max_end_time - min_start_time
		return attack_duration
	return 0
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
def get_http_flood_packets(packets):
	#func: get_http_flood_packets
	#args: packets -> 
	#Doccs: This function will return all the http packets, that have been detected as a DDoS attack
	burst_threshold = 100
	http_flood = []
	for p in packets:
		#Calculate packet rate
		#(endtime - start time) / packetnum
		if p["count"] > 1:
			http_rate = p["count"]/(p["End time"] - p["Start Time"])
		else:
			http_rate = p["count"]
		if http_rate > burst_threshold:
			#Packet is ICMP packet
			http_flood.append(p)
	return http_flood
def calculate_number_of_syn(tcp_handshakes):
	#func: calculate_percentage_of_syn
	#args: tcp_handshakes -> list of tcp handshakes.
	#Docs: This function is a helper function for 'check_syn_flood()'
	#Its calculates the percentage of incomplete handshake in TCP traffic
	c = 0
	for t in tcp_handshakes:
		if t.syn == True and t.ack == False:
			c = c +1
	return c
def get_tcp_incmplete_handshakes(tcp_list):
	#func: get_tcp_incmplete_handshakes
	#args: tcp_list ->
	#Docs: This function will calculate the percentage of uncomplete 3-way handshakes.
	#Count the number of IP's that have just sent SYN packets
	if len(tcp_list) > 0:
		tcp_handshakes = []
		for p in tcp_list:
			if p[TCP].flags == 0x02:
				#SYN packet
				#record the a SYN flag being sent
				tcp = TCP_packet(p)
				tcp_handshakes.append(tcp)
			elif p[TCP].flags == 0x10:
				#ACK - That is completing the hand shake
				#Check if packet is in the tcp_syn list
				for tcp in tcp_handshakes:
					if p.src == tcp.getSrc() and p.dst == tcp.getDst():
						tcp.ack = True
		return tcp_handshakes

def check_syn_flood(tcp_list):
	#func: syn_flood
	#args: None
	#Docs: This function will detected SYN flood attacks in the pcap file.
	#-----------------------------------------
	#Fix up this function-----------------------------------------
	#-----------------------------------------
	OUTPUT_REPORT = {"SYN FLOOD DETECTED": False}
	#Check 1: First check what percentage of tcp is a uncomplete 3-way handsahke
	#Check 2: Check how many different IPs the attack is coming from
	#Check 3: Check if its a bursty behavior
	tcp_handshakes = get_tcp_incmplete_handshakes(tcp_list)
	syn_percentage = calculate_number_of_syn(tcp_handshakes) / len(tcp_list)
	print(f"SYN packet: {syn_percentage}")
	if syn_percentage > 0.3:
		#SYN_flood
		OUTPUT_REPORT["SYN FLOOD DETECTED"] = True
		#Check 2
		syn_list_ips,target_ip,target_port = calculate_syn_from_ips(tcp_handshakes)
		OUTPUT_REPORT["packets"] = syn_list_ips
		#Calcuate average packet rate
		OUTPUT_REPORT["avg packet rate"] = calculate_avg_packet_rate(syn_list_ips)
		OUTPUT_REPORT["target ip"] = target_ip
		OUTPUT_REPORT["target port"] = target_port
		OUTPUT_REPORT["SYN Flood percentage"] = syn_percentage
		OUTPUT_REPORT["Attack Duration"] = calculate_Attack_Duration(syn_list_ips)
	else:
		OUTPUT_REPORT["SYN Flood percentage"] = 0
	return OUTPUT_REPORT
def check_udp_flood(udp_list):
	#func: udp_flood
	#args: None
	#Docs: This function will detect if there is a UDP flood attack in the pcap file.
	OUTPUT_REPORT = {"UDP FLOOD DETECTED": False}
	udp_flood = []

	udp_packets, target_ip = group_packts_by_ip(udp_list)
	#udp_packets, target_ip  = calculate_udp_from_ips(udp_list)
	
	#Get burst rate of UDP traffic
	udp_flood = get_udp_flood_packets(udp_packets)

	#Make report
	if len(udp_flood) > 0:
		#UDP packets have exceed UDP flood
		OUTPUT_REPORT["UDP FLOOD DETECTED"] = True
		OUTPUT_REPORT["packets"] = udp_flood
		OUTPUT_REPORT["target ip"] = target_ip
		OUTPUT_REPORT["avg packet rate"] = calculate_avg_packet_rate(udp_flood)
		OUTPUT_REPORT["Attack Duration"] = calculate_Attack_Duration(udp_flood)



	return OUTPUT_REPORT
def get_icmp_echo_packets(icmp_list):
	#func: get_icmp_echo_packets
	#args: None
	#Docs: This function will only get ICMP echo packets.
	#ICMP echo packets are used in DDoS attack where a attack sends echo packets
	echo_packets = []
	for p in icmp_list:
		if p[ICMP].type == 8:
			echo_packets.append(p)

	return echo_packets
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
def check_icmp_flood(icmp_list):
	#func: icmp_flood
	#args: None
	#Docs: This function will detect if there is an ICMP flood attack in the PCAP file.
	OUTPUT_REPORT = {"ICMP FLOOD DETECTED": False}
	#icmp_packets, target_ip  = calculate_icmp_from_ips(icmp_list)
	icmp_echo_list = get_icmp_echo_packets(icmp_list)
	icmp_packets, target_ip = group_packts_by_ip(icmp_echo_list)
	#Check the ICMP burst rate
	icmp_flood = get_icmp_flood_packets(icmp_packets)

	#
	if len(icmp_flood) > 0:
		OUTPUT_REPORT["ICMP FLOOD DETECTED"] = True
		OUTPUT_REPORT["target ip"] = target_ip
		OUTPUT_REPORT["packets"] = icmp_flood
		OUTPUT_REPORT["avg packet rate"] = calculate_avg_packet_rate(icmp_flood)
		OUTPUT_REPORT["Attack Duration"] = calculate_Attack_Duration(icmp_flood)



	return OUTPUT_REPORT
def check_http_get_flood(http_list):
	#func: check_http_get_flood
	#args: None
	#Doc: This function will detect if there is a HTTP-GET flood attack in the PCAP file.
	OUTPUT_REPORT = {"HTTP-GET FLOOD DETECTED": False}
	http_get_list = get_http_traffic_sent(http_list)
	http_traffic, _ = group_packts_by_ip(http_get_list)
	#http_traffic = calculate_http_from_ips(http_list)
	
	#Get all the http flood traffic
	http_flood_packets = get_http_flood_packets(http_traffic)

	if len(http_flood_packets) > 0:
		OUTPUT_REPORT["HTTP-GET FLOOD DETECTED"] = True
		OUTPUT_REPORT["target ip"] = "temp"
		OUTPUT_REPORT["packets"] = http_flood_packets
		OUTPUT_REPORT["avg packet rate"] = calculate_avg_packet_rate(http_flood_packets)
		OUTPUT_REPORT["Attack Duration"] = calculate_Attack_Duration(http_flood_packets)

	return OUTPUT_REPORT
def get_http_traffic_sent(http_list):
	#func: get_http_traffic_sent()
	#args: None
	#Docs: This function will filter all the http traffic and only return traffic that has a destination port = 80.
	http_sent = []
	for p in http_list:
		if p[TCP].dport == 80:
			http_sent.append(p)
	return http_sent
def analyze_network_traffic(data):
	#func: analyze_network_traffic
	#args: None
	#Docs: This function will analyze all the network traffic.

	#SYN flood
	tcp_list = data["tcp_list"]
	udp_list = data["udp_list"]
	icmp_list = data["icmp_list"]
	http_list = data["http_list"]
	
	#Check for TCP SYN Flood attack
	syn_flood_report = check_syn_flood(tcp_list)

	if syn_flood_report["SYN FLOOD DETECTED"] == True:
		print(Fore.RED+"SYN flood detected!")
		print(Fore.RED+"Details of the SYN flood will be included in the report")
	else:
		print(Fore.GREEN+"No SYN flood detected in PCAP")

	#Check UDP Flood attack
	udp_flood_report = check_udp_flood(udp_list)
	if udp_flood_report["UDP FLOOD DETECTED"] == True:
		print(Fore.RED+"UDP flood detected!")
		print(Fore.RED+"Details of the UDP flood will be included in the report")
	else:
		print(Fore.GREEN+"No UDP flood detected in PCAP")

	#Check ICMP Flood attack
	icmp_flood_report = check_icmp_flood(icmp_list)

	if icmp_flood_report["ICMP FLOOD DETECTED"] == True:
		print(Fore.RED+"ICMP flood detected!")
		print(Fore.RED+"Details of the UDP flood will be included in the report")
	else:
		print(Fore.GREEN+"No ICMP flood detected in PCAP")

	#Check ICMP Flood
	http_flood_report = check_http_get_flood(http_list)

	if http_flood_report["HTTP-GET FLOOD DETECTED"] == True:
		print(Fore.RED+"HTTP-GET flood detected!")
		print(Fore.RED+"Details of the HTTP-GET flood will be included in the report")
	else:
		print(Fore.GREEN+"No HTTP-GET flood detected in PCAP")

	return [syn_flood_report,udp_flood_report,icmp_flood_report,http_flood_report]


