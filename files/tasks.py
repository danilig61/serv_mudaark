import os
import tempfile
import io
from celery import shared_task
import requests
from .config import minio_client
from .models import File
import logging
from django.conf import settings

logger = logging.getLogger(__name__)

# Поддерживаемые MIME-типы для форматов
SUPPORTED_FORMATS = {
    '.mp4': 'video/mp4',
    '.mp3': 'audio/mpeg',
    '.wav': 'audio/wav',
    '.m4a': 'audio/mp4',
}

@shared_task(bind=True)
def process_file(self, file_id, file_path, analyze_text):
    logger.info(f"Начало задачи process_file для файла с ID: {file_id}")
    try:
        # Получение объекта файла
        file_instance = File.objects.get(id=file_id)
        file_instance.status = 'processing'
        file_instance.save()

        # Скачивание файла из MinIO
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            minio_client.fget_object(
                settings.AWS_STORAGE_BUCKET_NAME,
                file_path,
                temp_file.name
            )
            temp_file_path = temp_file.name

        # Проверка существования файла
        if not os.path.exists(temp_file_path):
            logger.error(f"Временный файл не найден: {temp_file_path}")
            file_instance.status = 'error'
            file_instance.save()
            return

        # Определение MIME-типа по расширению
        file_extension = os.path.splitext(file_path)[1].lower()
        mime_type = SUPPORTED_FORMATS.get(file_extension)

        if not mime_type:
            logger.error(f"Неподдерживаемый формат файла: {file_extension}")
            file_instance.status = 'error'
            file_instance.save()
            return

        logger.info(f"Отправка файла {file_path} на транскрипцию ({file_extension}).")

        # Отправка файла на API для транскрипции
        with open(temp_file_path, 'rb') as audio_file:
            response = requests.post(
                'http://94.130.54.172:8040/transcribe',
                files={'audio': (os.path.basename(file_path), audio_file, mime_type)}
            )

        if response.status_code == 200:
            # API возвращает SRT-файл в виде строки
            srt_content = response.text
            logger.info(f"Получен файл SRT, преобразование в текст.")

            # Преобразование SRT в текст
            transcription = convert_srt_to_text(srt_content)
            file_instance.transcription = transcription
            file_instance.status = 'completed'

            # Анализ текста, если требуется
            if analyze_text:
                logger.info(f"Отправка транскрипции на анализ.")
                analysis_response = requests.get(
                    'http://83.149.227.104/process_text',
                    params={'text': transcription}
                )
                if analysis_response.status_code == 200:
                    file_instance.analysis_result = analysis_response.json()
                else:
                    logger.error(f"Ошибка при анализе текста: {analysis_response.text}")
        else:
            logger.error(f"Ошибка при транскрипции: {response.text}")
            file_instance.status = 'error'

        # Сохранение изменений
        file_instance.save()

        # Удаление временного файла
        os.remove(temp_file_path)
        logger.info(f"Завершение задачи process_file для файла с ID: {file_id}")

    except Exception as e:
        logger.error(f"Ошибка при обработке файла: {e}")
        file_instance.status = 'error'
        file_instance.save()


def convert_srt_to_text(srt_content):
    # Преобразует содержимое SRT-файла в чистый текст.
    try:
        import re
        # Преобразование SRT из Unicode в читаемый текст
        decoded_content = srt_content.encode('latin1').decode('unicode_escape')
        # Убираем временные метки и порядковые номера
        lines = decoded_content.splitlines()
        text_lines = []
        for line in lines:
            # Пропускаем временные метки и числовые строки
            if re.match(r'^\d+$', line) or re.match(r'\d{2}:\d{2}:\d{2},\d{3}', line):
                continue
            # Добавляем текстовые строки
            if line.strip():
                text_lines.append(line.strip())

        return ' '.join(text_lines)
    except Exception as e:
        logger.error(f"Ошибка при преобразовании SRT в текст: {e}")
        return ""
