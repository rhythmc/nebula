class NaiveNCP:
	def __init__(self):
		pass

	def print_packet(self, pkt):
		payload = IP(pkt.get_payload())
		payload.show()

	def handle_outgoing_packet(self, pkt):
		print "Outgoing packet..."
		self.print_packet(pkt)
		pkt.accept()

	def handle_incoming_packet(self, pkt):
		print "Incoming packet..."
		self.print_packet(pkt)
		pkt.accept()
