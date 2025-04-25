from scapy.all import *
#List of all packets
icmp_list = []
quic_list = []
arp_list = []
http_list = []
tcp_list = []
udp_list = []
dns_list = []
mdns_list = []
ipv4_list = 0
ipv6_list = 0
packet_number = 0
other_packets = []
def expand(x):
	#func: expand
	#args: x -> x is the packet
	#Docs: This function will return the content of the packet
	#This function was from: https://stackoverflow.com/questions/13549294/get-all-the-layers-in-a-packet
	yield x.name
	while x.payload:
		x = x.payload
		yield x.name
def packetType(packet):
	#func: packetType
	#args: packet -> The packet that the function is checking
	#Docs: This function will classify if a packet is IPv4 or IPv6 packet
	global ipv4_list
	global ipv6_list
	if packet.haslayer(IP):
		ipv4_list = ipv4_list + 1
	elif packet.haslayer(IPv6):
		ipv6_list = ipv6_list + 1
def read_packets(packets):
	#funcs: read_packets
	#args: packets -> a list of all packets
	#Docs: This function will read all the packets and group them into there type
	global packet_number
	packet_number = len(packets)
	for p in packets:
		packetType(p)
		packet_content = list(expand(p))
		#check the types of packets
		if p.haslayer(DNS):
			#dns
			dns_list.append(p)
		elif p.haslayer(UDP) and (p[UDP].dport == 443 or p[UDP].sport == 443):
			#quic
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
			other_packets.append(p)
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
def capture_packets(args):
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
	packet_data = {
	"icmp_list": icmp_list,
	"quic_list": quic_list,
	"arp_list": arp_list,
	"http_list": http_list,
	"tcp_list": tcp_list,
	"udp_list": udp_list,
	"dns_list": dns_list,
	"mdns_list": mdns_list,
	"packet_number": packet_number,
	"other_packets": other_packets,
	"ipv4_list": ipv4_list,
	"ipv6_list" : ipv6_list,
	"FILE_NAME": FILE_NAME }
	return packet_data

	
