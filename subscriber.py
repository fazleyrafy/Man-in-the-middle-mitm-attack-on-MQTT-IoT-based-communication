import paho.mqtt.client as mqtt

BROKER_IP = "192.168.1.2"
TOPIC = "test"

def on_message(client, userdata, msg):
    payload = eval(msg.payload.decode())  # Convert string to list
    print(f"Received: {payload[0]}")

client = mqtt.Client()
client.on_message = on_message

client.connect(BROKER_IP, 1883)
client.subscribe(TOPIC)
client.loop_forever()
