FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN python manage.py makemigrations core
CMD ["sh", "-c", "python manage.py migrate --noinput && python seed.py && gunicorn -w 2 -b 0.0.0.0:5000 config.wsgi:application"]