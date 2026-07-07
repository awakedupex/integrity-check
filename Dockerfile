FROM python:3.11-slim

WORKDIR /app

COPY integrity_check.py .

ENTRYPOINT ["python", "integrity_check.py"]
CMD ["--help"]
