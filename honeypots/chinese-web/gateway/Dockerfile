FROM python:3.12-alpine

WORKDIR /app
COPY honeypots/chinese-web/server.py /app/server.py

ENV HONEYPOT_PROFILE=gateway \
    HONEYPOT_IMAGE_KEY=cn_iot_gateway \
    HONEYPOT_IMAGE_NAME=miragetrap/cn-iot-gateway-honeypot:latest

EXPOSE 80
CMD ["python", "/app/server.py"]
