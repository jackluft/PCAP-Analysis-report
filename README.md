# PCAP-Analysis-report
This program will analyze a pcap file inputed into the program and detected any DDoS attacks. The attack that it will scan for include TCP SYN flood, UDP Flood, ICMP Flood and HTTP-GET flood.
To get started run$ pip install -r requirements.txt. To install all the required libraies to run the program.

## Detecting SYN Flood attacks: 
This program will detect TCP SYN Flood attacks by calculating the number of incompleted 3-way handshakes and take the average of the incomplete handshakes based off all the TCP traffic.


