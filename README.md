# PCAP-Analysis-report
This program will analyze a pcap file inputed into the program and detected any DDoS attacks. The attack that it will scan for include TCP SYN flood, UDP Flood, ICMP Flood and HTTP-GET flood. The program will return a PDF document with its findings
## Installing required libraries
$ pip install -r requirements.txt
## Running the program 
$ python analyzer.py <file.pcap> <br> $ python analyzer.py <file.pcap> -n <output.pdf>

## Code structure
The code is broken down into 5 files. <br>
analyzer.py (The Main python program to execute) <br> detect_ddos.py (The python file that is responsible for the logic of the DDoS detection) <br> report_generator.py (The python file that is responsible for generating the PDF document in the proper format) <br> packetObject.py (Contains a TCP object used to calculate SYN Flood attack) <br>read_packets.py (The python file that will read that packets and organize the packets)

## Detecting SYN Flood attacks: 
This program will detect TCP SYN Flood attacks by calculating the number of incompleted 3-way handshakes and take the average of the incomplete handshakes based off all the TCP traffic. The implementation of this logic is in the check_syn_flood() function

## Detecting UDP Flood attacks:
This program will detect UDP Flood attacks by calculating the burst rate of the UDP packets.
The implementation of this logic is in the check_udp_flood() function


## Detecting ICMP Flood attacks:
This program will detect ICMP Flood attacks by calculating the ICMP Echo packets and calculating its packet rate. If the packet rate exceeds a threshold value its will be classified as a attack packet. The implementation of this logic is in the check_icmp_flood() function

## Detecting HTTP Flood attacks:
This program will detect HTTP-GET Flood attacks by analyzing the rate of incoming GET requests over time and flagging sources that exceed a specified request threshold, indicating potential DDoS activity. 



## Output:
The program will output a PDF document reporting all its findings in the PCAP file. The document will go into detail of what packets make up the PCAP file and details about the DDoS attacks it has detected (Find example output of file in: Example_output-file.pdf and in Example-output2.pdf). 

##Problems encountered
Some of the problems encountered in detecting DDoS attacks, is detecting UDP, ICMP, and HTTP GET floods. I initially encountered numerous false positives, as any high-rate UDP traffic
was flagged as suspicious, even though legitimate services like DNS and video streaming
often generate large volumes of UDP packets.
