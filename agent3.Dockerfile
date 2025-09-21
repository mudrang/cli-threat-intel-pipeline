FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY agent3_normalizer.py .
CMD ["python", "agent3_normalizer.py"]