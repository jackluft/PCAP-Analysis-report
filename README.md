# PCAP-Analysis-report
This program will analyze a pcap file inputed into the program and detected any DDoS attacks. The attack that it will scan for include TCP SYN flood, UDP Flood, ICMP Flood and HTTP-GET flood.
## Installing required libraries
$ pip install -r requirements.txt
## Running the program 
$ python analyzer.py <file.pcap>
## Detecting SYN Flood attacks: 
This program will detect TCP SYN Flood attacks by calculating the number of incompleted 3-way handshakes and take the average of the incomplete handshakes based off all the TCP traffic.

## Detecting UDP Flood attacks:

## Detecting ICMP Flood attacks:
This program will detect ICMP Flood attacks by calculating the ICMP Echo packets and calculating its packet rate. If the packet rate exceeds a threshold value its will be classified as a attack packet.


## Output:
The program will output a PDF document reporting all its findings in the PCAP file. The document will go into detail of what packets make up the PCAP file and details about the DDoS attacks it has detected.


