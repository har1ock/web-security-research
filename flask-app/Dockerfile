FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Спершу створюємо БД (один раз), потім запускаємо 2 воркери gunicorn
CMD ["sh", "-c", "python -c 'from app import init_db; init_db()' && gunicorn -w 2 -b 0.0.0.0:5000 app:app"]