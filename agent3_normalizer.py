import pika
import json
import re

# --- Configuration ---
RABBITMQ_HOST = 'localhost'
INPUT_QUEUE_NAME = 'ioc_to_normalize'
OUTPUT_QUEUE_NAME = 'ioc_to_summarize'

# --- The Callback Function (Transformation Logic) ---
def callback(ch, method, properties, body):
    """Receives an enriched message and transforms it into the normalized schema."""
    try:
        message = json.loads(body)
        ioc_value = message.get('ioc_value')
        source = message.get('source')
        raw_data = message.get('raw_data')

        print(f" [->] Received raw data for: {ioc_value} from {source}")

        # Initialize our clean, normalized dictionary
        normalized_ioc = {
            "ioc_value": ioc_value,
            "ioc_type": None,
            "threat_score": 0,
            "is_malicious": False,
            "tags": [],
            "source_data": [{ "source": source, "raw_data": raw_data }]
        }

        # --- Transformation Logic for AbuseIPDB ---
        if source == 'AbuseIPDB':
            # Determine IOC type (simple regex for this example)
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc_value):
                normalized_ioc['ioc_type'] = 'ipv4'
            else:
                normalized_ioc['ioc_type'] = 'domain'

            # Extract the core data points
            data = raw_data.get('data', {})
            score = data.get('abuseConfidenceScore', 0)
            normalized_ioc['threat_score'] = score
            normalized_ioc['is_malicious'] = data.get('isWhitelisted', False) is not True and score > 25

            # Extract tags from the most recent reports
            if 'reports' in data:
                report_comments = [report['comment'] for report in data['reports'][:5]]
                normalized_ioc['tags'] = list(set(report_comments)) # Get unique comments

        # --- (Future-proofing) ---
        # elif source == 'OTX':
        #     # Add transformation logic for OTX data here
        #     pass

        # Publish the new, normalized message to the next queue
        ch.basic_publish(
            exchange='',
            routing_key=OUTPUT_QUEUE_NAME,
            body=json.dumps(normalized_ioc),
            properties=pika.BasicProperties(delivery_mode=2)
        )
        print(f" [<-] Published NORMALIZED data for: {ioc_value}")

    except Exception as e:
        print(f"An error occurred with {ioc_value}: {e}")
    
    ch.basic_ack(delivery_tag=method.delivery_tag)

# --- RabbitMQ Connection and Consumer Loop ---
connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST))
channel = connection.channel()

channel.queue_declare(queue=INPUT_QUEUE_NAME, durable=True)
channel.queue_declare(queue=OUTPUT_QUEUE_NAME, durable=True)

channel.basic_consume(queue=INPUT_QUEUE_NAME, on_message_callback=callback)

print(' [*] Agent 3 (Normalizer) is waiting for messages. To exit press CTRL+C')
channel.start_consuming()