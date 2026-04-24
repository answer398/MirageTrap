FROM python:3.12-alpine

WORKDIR /app
COPY honeypots/chinese-web/server.py /app/server.py

ENV HONEYPOT_PROFILE=cms \
    HONEYPOT_IMAGE_KEY=cn_cms_portal \
    HONEYPOT_IMAGE_NAME=miragetrap/cn-cms-honeypot:latest

EXPOSE 80
CMD ["python", "/app/server.py"]
