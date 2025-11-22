FROM python:3.14-alpine
COPY rotate.py .
RUN pip install --no-cache-dir configargparse httpx
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "rotate.py"]
