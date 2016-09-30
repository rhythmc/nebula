#!/bin/bash

# Author Akshay Narayan
# Sept 28 2016
# 
# After running this, attach to the docker containers and run netcat to send traffic between them

NETNAME=nebulanet

net=$(docker network list | grep -c "$NETNAME")
if [[ net -eq 0 ]]
then
    docker network create --subnet 172.18.0.0/24 $NETNAME
else
    echo "Network already created"
fi

echo "Current containers"
docker ps -a
echo "Killing running nebula containers"
docker ps -a | grep "nebula" | awk '{print $1}' | xargs docker rm -f

docker run -e "NCPMODE=0" --privileged --net $NETNAME --ip 172.18.0.5 --name nebula1 -itd nebula:0.01
docker run -e "NCPMODE=1" --privileged --net $NETNAME --ip 172.18.0.6 --name nebula2 -itd nebula:0.01
