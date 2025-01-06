FROM python:3.12-slim

WORKDIR /app

ENV LOG_LEVEL=DEBUG

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT ["python", "main.py"]
