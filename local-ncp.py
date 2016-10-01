"""

Implementation of a Network Control Point (NCP) directly at the end-host in
order to bypass the end-host<->NCP channel.

This works by using iptables/netfilter to intercept packets right before they
go on / come off of the wire and modifying them to add/remove our custom
headers (or do something else like rate limiting). In order for this to work,
the necessary iptables rules must be added to forward packets to this script
(see below).

===============================================================================

Assuming that you are talking to an end host at HOST:PORT using UDP...
(If this is not the case, simply change the match rules (src,dst,dport),
but leave the table and queue information the same)

1. Setup netfilter using (either)...

    (A) iptables (predecessor to nftables, less efficient, but I know it works)

        # Outgoing queue: [A]dd a rule to mangle table's OUTPUT chain to send all
        # UDP packets for [X:Y] to NFQUEUE #1
        sudo iptables -t mangle -A OUTPUT -p udp --dst [X] --dport [Y] -j NFQUEUE --queue-num 1
        # Incoming queue: [A]dd a rule to mangle table's PREROUTING chain to send
        # all UDP packets from [X:Y] to NFQUEUE #2
        sudo iptables -t mangle -A PREROUTING -p udp --src [X] --dport [Y] -j NFQUEUE --queue-num 2

    (B) nftables (newer, supposedly more efficient, haven't used it before)

        sudo nft add rule route output udp ip daddr [X] dport [Y] queue num 1
        sudo nft add rule route prerouting udp ip saddr[X] sport[Y] queue num 2

2. Run two instances of this script (one for each direction)

    sudo python local-ncp.py

===============================================================================

To view stats cat /proc/net/netfilter/nfnetlink_queue. The fields are:

    1. Queue ID
    2. Bound process ID
    3. Number of currently queued packets
    4. Copy mode
    5. Copy size
    6. Number of packets dropped due to reaching max queue size
    7. Number of packets dropped due to netlink socket failure
    8. Total number of packets sent to queue
    9. Something for libnetfilter_queue's internal use

===============================================================================

MIT NMS Nebula Project
Created: September 2016
Frank Cangialosi <frankc@csail.mit.edu>, ...

"""

import time
from netfilterqueue import NetfilterQueue, COPY_PACKET
from multiprocessing import Process
from ncp.NaiveNCP import NaiveNCP
from ncp.RateLimitingNCP import RateLimitingNCP
###############################################################################

OUT_QUEUE_ID = 1
IN_QUEUE_ID = 2
MAXQ = 100 # Arbitrarily chosen for now
MODE = COPY_PACKET # change to COPY_META to only get meta data
PACKETS_PER_SECOND = 3
###############################################################################

if __name__ == "__main__":
    # Setup NCP
    ncp = RateLimitingNCP(PACKETS_PER_SECOND) #NaiveNcp()

    # Create queues, register packet handlers
    inq = NetfilterQueue()
    outq = NetfilterQueue()
    inq.bind(IN_QUEUE_ID, ncp.handle_incoming_packet, max_len=MAXQ, mode=MODE)
    outq.bind(OUT_QUEUE_ID, ncp.handle_outgoing_packet, max_len=MAXQ, mode=MODE)

    # Start receiving packets
    try:
        print "Starting nfqueues..."
        inq_proc = Process(target=inq.run)
        outq_proc = Process(target=outq.run)
        inq_proc.start()
        outq_proc.start()
        inq_proc.join()
        outq_proc.join()
        print "Waiting for ctrl+c..."
    except KeyboardInterrupt:
        print "Received keyboard interrupt, quitting..."
