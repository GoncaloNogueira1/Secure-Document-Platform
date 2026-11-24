FROM python:3.11-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends qpdf ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY analyzer_logging.py .
COPY app.py .

EXPOSE 9000

CMD ["python", "app.py"]
