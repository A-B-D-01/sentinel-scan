FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Install additional requirements added during Phase 6-9
RUN pip install --no-cache-dir Flask-Login Flask-WTF Flask-Talisman

ENV FLASK_APP=app/app.py
ENV FLASK_ENV=production

EXPOSE 5000

CMD ["python", "app/app.py"]
