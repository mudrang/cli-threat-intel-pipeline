FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY agent4_summarizer.py .
CMD ["python", "agent4_summarizer.py"]