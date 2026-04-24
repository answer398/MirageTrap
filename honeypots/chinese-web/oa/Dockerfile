FROM python:3.12-alpine

WORKDIR /app
COPY honeypots/chinese-web/server.py /app/server.py

ENV HONEYPOT_PROFILE=oa \
    HONEYPOT_IMAGE_KEY=cn_oa_portal \
    HONEYPOT_IMAGE_NAME=miragetrap/cn-oa-honeypot:latest

EXPOSE 80
CMD ["python", "/app/server.py"]
