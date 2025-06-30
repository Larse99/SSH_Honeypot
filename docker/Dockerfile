FROM python:3.13-slim

RUN pip install paramiko logging

COPY app /app

WORKDIR /app

CMD ["python", "main.py"]
