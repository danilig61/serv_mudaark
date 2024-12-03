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
def srt_to_text(srt_content):
    """Преобразует SRT-субтитры в обычный текст."""
    lines = srt_content.split("\n")
    text_lines = []
    for line in lines:
        # Пропускаем строки с номером и временными метками
        if "-->" not in line and not line.strip().isdigit():
            text_lines.append(line.strip())
    return " ".join(text_lines).strip()


@shared_task(bind=True)
def process_file(self, file_id, file_path, analyze_text):
    logger.info(f"Начало задачи process_file для файла с ID: {file_id}")
    try:
        file_instance = File.objects.get(id=file_id)
        file_instance.status = 'processing'
        file_instance.save()

        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            minio_client.fget_object(
                settings.AWS_STORAGE_BUCKET_NAME,
                file_path,
                temp_file.name
            )
            temp_file_path = temp_file.name

        if not os.path.exists(temp_file_path):
            logger.error(f"Временный файл не найден: {temp_file_path}")
            file_instance.status = 'error'
            file_instance.save()
            return

        file_extension = os.path.splitext(file_path)[1].lower()
        mime_type = SUPPORTED_FORMATS.get(file_extension)

        if not mime_type:
            logger.error(f"Неподдерживаемый формат файла: {file_extension}")
            file_instance.status = 'error'
            file_instance.save()
            return

        logger.info(f"Отправка файла {file_path} на транскрипцию ({file_extension}).")

        with open(temp_file_path, 'rb') as audio_file:
            response = requests.post(
                'http://94.130.54.172:8040/transcribe',
                files={'audio': (os.path.basename(file_path), audio_file, mime_type)}
            )

        if response.status_code == 200:
            srt_transcription = response.text  # Получаем SRT
            transcription_text = srt_to_text(srt_transcription)  # Преобразуем в текст
            logger.info(f"Получена транскрипция: {transcription_text}")
            file_instance.transcription = transcription_text
            file_instance.status = 'completed'

            if analyze_text:
                logger.info(f"Отправка транскрипции на анализ.")
                analysis_response = requests.get(
                    'http://83.149.227.104/process_text',
                    params={'text': transcription_text}
                )
                if analysis_response.status_code == 200:
                    file_instance.analysis_result = analysis_response.json()
                else:
                    logger.error(f"Ошибка при анализе текста: {analysis_response.text}")
        else:
            logger.error(f"Ошибка при транскрипции: {response.text}")
            file_instance.status = 'error'

        file_instance.save()
        os.remove(temp_file_path)
        logger.info(f"Завершение задачи process_file для файла с ID: {file_id}")

    except Exception as e:
        logger.error(f"Ошибка при обработке файла: {e}")
        file_instance.status = 'error'
        file_instance.save()

