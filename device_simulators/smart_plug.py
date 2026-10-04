import paho.mqtt.client as mqtt
import time
import random

BROKER = "localhost"
PORT = 1883
TOPIC = "home/smartplug/status"

client = mqtt.Client()
client.connect(BROKER, PORT, 60)

while True:
    power_watts = round(random.uniform(5, 150), 1)  # simulate a device drawing power
    status = "ON" if power_watts > 5 else "OFF"
    payload = f'{{"status": "{status}", "power_watts": {power_watts}}}'

    client.publish(TOPIC, payload)
    print(f"Published: {payload}")

    time.sleep(7)
