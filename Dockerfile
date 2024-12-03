# Используем базовый образ Python
FROM python:3.10-slim

# Устанавливаем необходимые зависимости
RUN apt-get update && apt-get install -y \
    ffmpeg \
    libavcodec-extra \
    && rm -rf /var/lib/apt/lists/*

# Устанавливаем рабочую директорию
WORKDIR /code

# Копируем файл requirements.txt и устанавливаем зависимости Python
COPY requirements.txt /code/
RUN pip install -r requirements.txt

# Копируем остальные файлы приложения
COPY . /code/

# Указываем команду для запуска Celery worker
CMD ["celery", "-A", "mudaark", "worker", "--loglevel=info"]
