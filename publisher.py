import paho.mqtt.publish as publish
import random
import time

host = "192.168.1.2" 
topic = "test"

try:
    while True:
        random_value = random.randint(1, 20)
        payload = [random_value]
        
        publish.single(topic=topic, payload=str(payload), hostname=host, qos=0)
        # print(f"Published: {payload}")
        
        time.sleep(1)  # Wait 2 seconds between messages
        
except KeyboardInterrupt:
    print("\nPublisher stopped.")
