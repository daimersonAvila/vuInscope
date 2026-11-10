FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 APP_ENV=production DATABASE_PATH=/data/vulnscope.db
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && useradd --system --uid 10001 app && mkdir /data && chown app /data
COPY src ./src
COPY wsgi.py .
USER app
VOLUME /data
EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/healthz')" || exit 1
# One worker + threads keeps the in-memory rate limiter / lockout consistent. See README to scale out.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "8", "--timeout", "60", "--limit-request-line", "4094", "wsgi:app"]
