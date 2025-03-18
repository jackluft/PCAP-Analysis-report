import argparse
from read_packets import capture_packets
from detect_ddos import analyze_network_traffic
from report_generator import PDFreport
def parse_args():
	parser = argparse.ArgumentParser(description="Read A PCAP file, gives summary of network content")
	parser.add_argument("pcap_file",help="Path to the PCAP file")
	parser.add_argument("-n","--filename",type=str,default="output-report.pdf",help="Set the name of the output PDF file")
	args = parser.parse_args()

	return args

def main():

	args = parse_args()
	pcap_file_name = args.pcap_file
	#Organize all the packets
	packets = capture_packets(args)

	#Detect DDoS attacks
	traffic_results = analyze_network_traffic(packets)

	#Generate PDF Document
	PDFreport(pcap_file_name,traffic_results,packets)




main()
