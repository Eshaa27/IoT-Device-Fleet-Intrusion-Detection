import paho.mqtt.client as mqtt
import time
import random

BROKER = "localhost"  # Mosquitto is running on the same machine
PORT = 1883
TOPIC = "home/thermostat/temperature"

client = mqtt.Client()
client.connect(BROKER, PORT, 60)

current_temp = 23.0  # starting point

while True:
    # Simulate a small, realistic change in temperature
    current_temp += random.uniform(-0.3, 0.3)
    payload = f"{current_temp:.1f}"

    client.publish(TOPIC, payload)
    print(f"Published temperature: {payload}°C to {TOPIC}")

    time.sleep(5)  # wait 5 seconds before sending the next reading
