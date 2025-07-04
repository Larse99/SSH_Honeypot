FROM python:3.13-slim

RUN pip install paramiko logging requests

COPY app /app

WORKDIR /app

CMD ["python", "main.py"]
