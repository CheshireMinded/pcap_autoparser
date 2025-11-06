FROM python:3.11-slim
RUN apt-get update && apt-get install -y tshark && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PYTHONUNBUFFERED=1
CMD ["python","pcap_autoparser_pro.py","tests/samples","--profile","noc","--deep","--csv"]
