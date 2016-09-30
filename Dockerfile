FROM ubuntu:16.04
MAINTAINER Akshay Narayan

RUN apt-get update
RUN apt-get install -y build-essential iptables nftables net-tools iperf python-dev python-pip libnetfilter-queue-dev iputils-ping netcat tcpdump
RUN pip install --upgrade pip
RUN pip install scapy NetfilterQueue multiprocessing

ENV NEBULA1 172.18.0.5
ENV NEBULA2 172.18.0.6
ENV PORT 42424

COPY iptables.sh /iptables.sh
COPY local-ncp.py /local-ncp.py

ENTRYPOINT ["bash", "/iptables.sh"]
