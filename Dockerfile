FROM python:3.12-slim
WORKDIR /service
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ app/
RUN useradd --system --uid 10001 demo && mkdir /data && chown demo:demo /data
USER demo
ENV SENTINEL_DEMO_MODE=1 SENTINEL_DB_PATH=/data/sentinel.sqlite
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]