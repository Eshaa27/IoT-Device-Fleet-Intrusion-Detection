import os
from pathlib import Path

import paho.mqtt.client as mqtt
import psycopg2
from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / ".env")

BROKER = "localhost"
PORT = 1883

db_config = {
    "host": os.getenv("POSTGRES_HOST", "localhost"),
    "port": os.getenv("POSTGRES_PORT", "5432"),
    "dbname": os.getenv("POSTGRES_DB"),
    "user": os.getenv("POSTGRES_USER"),
    "password": os.getenv("POSTGRES_PASSWORD"),
}
missing_settings = [name for name, value in db_config.items() if not value]
if missing_settings:
    raise RuntimeError(
        "Set these database settings in .env: " + ", ".join(missing_settings)
    )

conn = psycopg2.connect(**db_config)
cursor = conn.cursor()

def on_connect(client, userdata, flags, rc):
    print("Connected to MQTT broker, subscribing to all topics...")
    client.subscribe("home/#")  # the '#' means "subscribe to everything under home/"

def on_message(client, userdata, msg):
    topic = msg.topic
    payload = msg.payload.decode()
    print(f"Received: {topic} -> {payload}")

    cursor.execute(
        "INSERT INTO device_telemetry (topic, payload) VALUES (%s, %s)",
        (topic, payload)
    )
    conn.commit()

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

client.connect(BROKER, PORT, 60)
client.loop_forever()
