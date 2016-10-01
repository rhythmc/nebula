from scapy.all import *

class RateLimitingNCP:
    def __init__(self, pkt_per_sec):
        self.pkt_per_sec = pkt_per_sec
        self.allowance = pkt_per_sec
        self.t_old = time.time()
        self.RTT = {}

    def handle_outgoing_packet(self, pkt):
        """
        Only allow self.pkt_per_sec packets to be sent each second,
        start dropping once this limit has been reached
        """
        t_now = time.time()
        t_delta = t_now - self.t_old
        self.t_old = t_now
        self.allowance += t_delta * self.pkt_per_sec
        self.allowance = min(self.allowance, self.pkt_per_sec)
        if self.allowance < 1.0:
            #print "Dropping packet, allowance={}".format(self.allowance)
            pkt.drop()
        else:
            #print "Accepting packet, allowance={}".format(self.allowance)
            payload = IP(pkt.get_payload())
            if payload.getlayer(1).name=="TCP":

                # MODIFY
                t1,t3 = payload[IP][payload.getlayer(1).name].options[2][1]
                payload[IP][payload.getlayer(1).name].options[2] = ('Timestamp', (t1+1,t3))

                str1 = payload[IP].src + " " + payload[IP].dst+" "
                str1 += payload.getlayer(1).name + " "
                str1 += str(payload[IP][payload.getlayer(1).name].sport)
                str1 += str(payload[IP][payload.getlayer(1).name].dport)
                seq_n = str(payload[IP][payload.getlayer(1).name].seq + len(payload[IP][payload.getlayer(1).name].payload))
                print "[{t}] Outgoing: {src}:{sport}->{dst}:{dport}, seq={seq}, len={pay_len}, tsv={tsv}, t1={t1}".format(
                    t=t_now,
                    src=payload[IP].src,
                    sport=payload[IP][payload.getlayer(1).name].sport,
                    dst=payload[IP].dst,
                    dport=payload[IP][payload.getlayer(1).name].dport,
                    seq=payload[IP][payload.getlayer(1).name].seq,
                    pay_len=len(payload[IP][payload.getlayer(1).name].payload),
                    tsv=payload[IP][payload.getlayer(1).name].options[2][1],
                    t1=t1
                )
                if str1 in self.RTT.keys():
                    self.RTT[str1][seq_n] = t_now
                else:
                    self.RTT[str1] ={}
                    self.RTT[str1][seq_n] = t_now
            del payload[IP][payload.getlayer(1).name].chksum
            pkt.set_payload(str(payload))
            pkt.accept()
            self.allowance -= 1.0

    def handle_incoming_packet(self, pkt):
        """
        Allow all incoming packets
        """
        t_now = time.time()
        payload = IP(pkt.get_payload())
        if payload.getlayer(1).name=="TCP":
            print "[{t}] Incoming: {src}:{sport}->{dst}:{dport}, ack={ack}, len={pay_len}, tsv={tsv}".format(
                t=t_now,
                src=payload[IP].src,
                sport=payload[IP][payload.getlayer(1).name].sport,
                dst=payload[IP].dst,
                dport=payload[IP][payload.getlayer(1).name].dport,
                ack=payload[IP][payload.getlayer(1).name].ack,
                pay_len=len(payload[IP][payload.getlayer(1).name].payload),
                tsv=payload[IP][payload.getlayer(1).name].options[2][1]
            )
        pkt.accept()
