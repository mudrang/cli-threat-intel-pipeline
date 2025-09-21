import pika
import json
import requests
import os
import time

# --- Configuration ---
RABBITMQ_HOST = 'localhost'
INPUT_QUEUE_NAME = 'ioc_to_enrich'
OUTPUT_QUEUE_NAME = 'ioc_to_normalize'
# IMPORTANT: Store your API key as an environment variable, not in the code.
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check'

if not ABUSEIPDB_API_KEY:
    print("Error: ABUSEIPDB_API_KEY environment variable not set.")
    exit()

# --- The Callback Function (This is where the work happens) ---
def callback(ch, method, properties, body):
    """This function is called every time a message is received."""
    try:
        message = json.loads(body)
        ioc_value = message.get('ioc_value')
        print(f" [->] Received IOC: {ioc_value}")

        # Prepare the API request
        headers = {
            'Accept': 'application/json',
            'Key': ABUSEIPDB_API_KEY
        }
        params = {
            'ipAddress': ioc_value,
            'maxAgeInDays': '90'
        }

        # Make the API call
        response = requests.get(url=ABUSEIPDB_URL, headers=headers, params=params)
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
        
        enrichment_data = response.json()

        # Prepare the output message
        output_message = {
            'ioc_value': ioc_value,
            'source': 'AbuseIPDB',
            'raw_data': enrichment_data
        }

        # Publish the enriched data to the next queue
        ch.basic_publish(
            exchange='',
            routing_key=OUTPUT_QUEUE_NAME,
            body=json.dumps(output_message),
            properties=pika.BasicProperties(delivery_mode=2)
        )
        print(f" [<-] Published enrichment for: {ioc_value}")

    except requests.exceptions.HTTPError as err:
        print(f"HTTP Error for {ioc_value}: {err}")
    except Exception as e:
        print(f"An error occurred with {ioc_value}: {e}")
    
    # Acknowledge that the message has been successfully processed.
    ch.basic_ack(delivery_tag=method.delivery_tag)

# --- RabbitMQ Connection and Consumer Loop ---
connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST))
channel = connection.channel()

channel.queue_declare(queue=INPUT_QUEUE_NAME, durable=True)
channel.queue_declare(queue=OUTPUT_QUEUE_NAME, durable=True)

# Set up the subscription to the input queue
channel.basic_consume(queue=INPUT_QUEUE_NAME, on_message_callback=callback)

print(' [*] Agent 2 (AbuseIPDB) is waiting for messages. To exit press CTRL+C')
channel.start_consuming()