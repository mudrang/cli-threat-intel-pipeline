import sys, os, re, json, pika
from scapy.all import rdpcap, IP, DNS, DNSQR, DNSRR, TCP
from scapy.layers.tls.handshake import TLSClientHello

def is_private_ip(ip):
    private_ranges = [re.compile("^10\."), re.compile("^172\.(1[6-9]|2[0-9]|3[0-1])\."), re.compile("^192\.168\.")]
    return any(pattern.match(ip) for pattern in private_ranges)

def process_pcap_and_publish(pcap_file_path):
    found_iocs = set()
    try:
        packets = rdpcap(pcap_file_path)
        for packet in packets:
            if packet.haslayer(IP):
                src_ip, dst_ip = packet[IP].src, packet[IP].dst
                if not is_private_ip(src_ip): found_iocs.add(src_ip)
                if not is_private_ip(dst_ip): found_iocs.add(dst_ip)
            if packet.haslayer(DNS) and packet[DNS].opcode == 0 and packet[DNS].rcode == 0:
                if packet[DNS].qr == 0 and packet.haslayer(DNSQR):
                    try: found_iocs.add(packet[DNSQR].qname.decode('utf-8').rstrip('.'))
                    except: continue
                elif packet[DNS].qr == 1 and packet[DNS].ancount > 0 and packet.haslayer(DNSRR):
                    for i in range(packet[DNS].ancount):
                        try:
                            dns_rr = packet[DNS].an[i]
                            if dns_rr.type == 1: found_iocs.add(dns_rr.rdata)
                            elif dns_rr.type == 5: found_iocs.add(dns_rr.rdata.decode('utf-8').rstrip('.'))
                        except: continue
            if packet.haslayer(TLSClientHello):
                for ext in packet[TLSClientHello].extensions:
                    if ext.type == 0:
                        try: found_iocs.add(ext.servernames[0].servername.decode('utf-8'))
                        except: continue
            if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80) and hasattr(packet[TCP], 'load'):
                try:
                    payload = packet[TCP].load.decode('utf-8', errors='ignore')
                    match = re.search(r"Host: ([a-zA-Z0-9\.\-]+)", payload)
                    if match: found_iocs.add(match.group(1))
                except: continue
    except Exception as e:
        print(f"Scapy error: {e}"); return 0
    if not found_iocs: return 0
    try:
        connection = pika.BlockingConnection(pika.ConnectionParameters('rabbitmq'))
        channel = connection.channel()
        queue_name = 'ioc_to_enrich'
        channel.queue_declare(queue=queue_name, durable=True)
        for ioc in sorted(list(found_iocs)):
            message = {'ioc_value': ioc, 'source_agent': 'agent_1_ioc_extractor'}
            channel.basic_publish(exchange='', routing_key=queue_name, body=json.dumps(message), properties=pika.BasicProperties(delivery_mode=2))
        connection.close()
        return len(found_iocs)
    except Exception as e:
        print(f"RabbitMQ error: {e}"); return 0