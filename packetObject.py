from scapy.all import IP, IPv6
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
		if self.packet.haslayer(IP):
			return self.packet[IP].src
		elif self.packet.haslayer(IPv6):
			return self.packet[IPv6].src
	def getDst(self):
		if self.packet.haslayer(IP):
			return self.packet[IP].dst
		elif self.packet.haslayer(IPv6):
			return self.packet[IPv6].dst
	def getTime(self):
		if self.packet.haslayer(IP):
			return self.packet[IP].time
		elif self.packet.haslayer(IPv6):
			return self.packet

