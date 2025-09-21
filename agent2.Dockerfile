# Start with a Python base image
FROM python:3.11-slim

# Set the working directory inside the container
WORKDIR /app

# Copy and install the requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the agent's script into the container
COPY agent2_abuseipdb.py .

# The command to run when the container starts
CMD ["python", "agent2_abuseipdb.py"]