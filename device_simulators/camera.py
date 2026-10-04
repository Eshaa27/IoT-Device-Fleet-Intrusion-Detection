import paho.mqtt.client as mqtt
import time
import random

BROKER = "localhost"
PORT = 1883
TOPIC = "home/camera/motion"

client = mqtt.Client()
client.connect(BROKER, PORT, 60)

while True:
    motion_detected = random.choice([True, False, False, False])  # motion is rarer than "no motion"
    payload = f'{{"motion_detected": {str(motion_detected).lower()}}}'

    client.publish(TOPIC, payload)
    print(f"Published: {payload}")

    time.sleep(10)
