from scapy.all import IP
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

