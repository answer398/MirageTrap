FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && \
    pip install --no-cache-dir \
    -i https://pypi.tuna.tsinghua.edu.cn/simple \
    --default-timeout=600 \
    --retries 10 \
    -r /app/requirements.txt

COPY backend /app

RUN useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 15000

CMD ["sh", "-c", "flask --app manage.py db upgrade && gunicorn -b 0.0.0.0:${APP_PORT:-15000} manage:app --workers ${GUNICORN_WORKERS:-2} --threads ${GUNICORN_THREADS:-4} --timeout 60"]
