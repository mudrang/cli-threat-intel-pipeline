import streamlit as st
import pika
import json
import time
import pandas as pd
from agent1_script import extract_and_publish_iocs # Import our refactored function

# --- Page Configuration ---
st.set_page_config(page_title="Threat Intel Pipeline", layout="wide")
st.title("🕵️‍♂️ Agent-Driven Threat Intelligence Pipeline")

# --- File Uploader ---
uploaded_file = st.file_uploader("Choose a .pcap file", type="pcap")

if uploaded_file is not None:
    if st.button("Analyze PCAP File"):
        with st.spinner('Agent 1 is processing the file...'):
            # Save the uploaded file temporarily to be processed
            with open("temp.pcap", "wb") as f:
                f.write(uploaded_file.getbuffer())
            
            # Trigger Agent 1
            ioc_count = extract_and_publish_iocs("temp.pcap")
            st.success(f"Agent 1 found and published {ioc_count} IOCs to the queue.")

        # This part acts like Agent 5, fetching the final results
        with st.spinner('Agents 2, 3, and 4 are working... This may take a moment.'):
            results = []
            # Wait a bit for messages to process
            time.sleep(10) 
            
            connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
            channel = connection.channel()
            queue_name = 'ioc_to_report'
            
            # Drain the queue
            while True:
                method_frame, header_frame, body = channel.basic_get(queue=queue_name)
                if method_frame is None:
                    break
                results.append(json.loads(body))
                channel.basic_ack(method_frame.delivery_tag)

            connection.close()

        st.success(f"All agents have finished. Received {len(results)} final reports.")

        # --- Display the Report ---
        if results:
            df = pd.DataFrame(results)
            
            # Color-coding for the report
            def color_recommendation(val):
                color = 'white'
                if val == 'block':
                    color = '#ffcccc'
                elif val == 'monitor':
                    color = '#fff8cc'
                return f'background-color: {color}'

            st.dataframe(df.style.applymap(color_recommendation, subset=['recommendation']))