FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt aegis-2fauth-importer.py ./
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

CMD ["python", "aegis-2fauth-importer.py"]
