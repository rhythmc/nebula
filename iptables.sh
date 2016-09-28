#!/bin/bash

# Author Akshay Narayan
# Sept 28 2016

set -x

if [[ -z $NCPMODE ]]
then
    echo "Must specify NCPMODE env var"
    exit 1
fi

if [[ $NCPMODE -eq 0 ]]
then # NEBULA1 = 172.18.0.5
    iptables -t mangle -A OUTPUT -p udp --dst $NEBULA2 -j NFQUEUE --queue-num 1
    iptables -t mangle -A PREROUTING -p udp --src $NEBULA2 -j NFQUEUE --queue-num 2
else # NEBULA2 = 172.18.0.6
    iptables -t mangle -A OUTPUT -p udp --dst $NEBULA1 -j NFQUEUE --queue-num 1
    iptables -t mangle -A PREROUTING -p udp --src $NEBULA1 -j NFQUEUE --queue-num 2
fi

python /local-ncp.py
