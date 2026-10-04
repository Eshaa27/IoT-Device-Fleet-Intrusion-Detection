import paho.mqtt.client as mqtt
import time
import random

BROKER = "localhost"
PORT = 1883
TOPIC = "home/router/status"

client = mqtt.Client()
client.connect(BROKER, PORT, 60)

while True:
    connected_devices = random.randint(3, 12)
    traffic_mb = round(random.uniform(1, 50), 2)
    payload = f'{{"connected_devices": {connected_devices}, "traffic_mb": {traffic_mb}}}'

    client.publish(TOPIC, payload)
    print(f"Published: {payload}")

    time.sleep(8)
