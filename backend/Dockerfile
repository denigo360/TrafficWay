FROM python:3.14-slim

WORKDIR /backend

RUN apt-get update && apt-get install -y

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["gunicorn", "backend.main:app", "-k", "uvicorn.workers.UvicornWorker", "--worker-class", "asgi", "--bind", "0.0.0.0:8000"]
