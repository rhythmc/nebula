Running
-------

./run.sh

Will boot two containers, set up iptables rules, and start an incoming and outgoing NCP on each.
After booting the containers, attach to the them and run netcat to send traffic between them.
Currently only UDP traffic is captured; this behavior can be modified in iptables.sh

Dependencies
------------

docker
