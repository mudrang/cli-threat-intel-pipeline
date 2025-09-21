import pika
import json

# --- Configuration ---
RABBITMQ_HOST = 'localhost'
INPUT_QUEUE_NAME = 'ioc_to_summarize'
OUTPUT_QUEUE_NAME = 'ioc_to_report'

# --- The Callback Function (Decision-Making Logic) ---
def callback(ch, method, properties, body):
    """Receives a normalized message and adds a summary and recommendation."""
    try:
        # The message from Agent 3 is already clean and structured
        normalized_ioc = json.loads(body)
        ioc_value = normalized_ioc.get('ioc_value')
        threat_score = normalized_ioc.get('threat_score', 0)

        print(f" [->] Received NORMALIZED data for: {ioc_value}")

        # --- Decision-Making Logic ---
        if threat_score > 75:
            normalized_ioc['recommendation'] = 'block'
            normalized_ioc['summary'] = (
                f"This IOC ({ioc_value}) has a high threat score of {threat_score}. "
                "It is associated with high-confidence malicious activity and should be blocked immediately."
            )
        elif threat_score > 25:
            normalized_ioc['recommendation'] = 'monitor'
            normalized_ioc['summary'] = (
                f"This IOC ({ioc_value}) has a moderate threat score of {threat_score}. "
                "It shows signs of suspicious activity and warrants further investigation. Monitor for any related traffic."
            )
        else:
            normalized_ioc['recommendation'] = 'ignore'
            normalized_ioc['summary'] = (
                f"This IOC ({ioc_value}) has a low threat score of {threat_score}. "
                "It shows no significant signs of malicious activity at this time."
            )
        
        # Publish the final, fully-enriched message to the next queue
        ch.basic_publish(
            exchange='',
            routing_key=OUTPUT_QUEUE_NAME,
            body=json.dumps(normalized_ioc),
            properties=pika.BasicProperties(delivery_mode=2)
        )
        print(f" [<-] Published FINAL analysis for: {ioc_value}")

    except Exception as e:
        print(f"An error occurred with {ioc_value}: {e}")
    
    ch.basic_ack(delivery_tag=method.delivery_tag)

# --- RabbitMQ Connection and Consumer Loop ---
connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST))
channel = connection.channel()

channel.queue_declare(queue=INPUT_QUEUE_NAME, durable=True)
channel.queue_declare(queue=OUTPUT_QUEUE_NAME, durable=True)

channel.basic_consume(queue=INPUT_QUEUE_NAME, on_message_callback=callback)

print(' [*] Agent 4 (Summarizer) is waiting for messages. To exit press CTRL+C')
channel.start_consuming()