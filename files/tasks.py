import os
from celery import shared_task
import requests
import moviepy.editor as mp
from .config import minio_client
from .models import File
import logging
import tempfile
import io
from django.conf import settings
from pydub import AudioSegment
from pydub.utils import which

logger = logging.getLogger(__name__)

# Указываем путь к ffmpeg и ffprobe
AudioSegment.converter = which("ffmpeg")
AudioSegment.ffprobe = which("ffprobe")

@shared_task(bind=True)
def process_file(self, file_id, file_path, analyze_text):
    logger.info(f"Начало задачи process_file для файла с ID: {file_id}")
    try:
        # Получение объекта файла
        file_instance = File.objects.get(id=file_id)
        file_instance.status = 'processing'
        file_instance.save()

        # Проверка существования файла перед началом обработки
        if not File.objects.filter(id=file_id).exists():
            logger.info(f"Файл {file_id} был удален. Остановка задачи.")
            return

        # Скачивание файла из MinIO
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            minio_client.fget_object(
                settings.AWS_STORAGE_BUCKET_NAME,
                file_path,
                temp_file.name
            )
            temp_file_path = temp_file.name

        # Проверка существования файла перед обработкой
        if not os.path.exists(temp_file_path):
            logger.error(f"Временный файл не найден: {temp_file_path}")
            return

        file_extension = os.path.splitext(file_path)[1].lower()

        # Обработка видео и аудио файлов
        if file_extension in ['.mp4']:
            clip = mp.VideoFileClip(temp_file_path)
            total_seconds = int(clip.duration)
            duration = f"{total_seconds // 60} мин {total_seconds % 60} сек"
            file_instance.duration = duration
            file_instance.save()

            # Извлечение аудиодорожки в WAV
            with tempfile.NamedTemporaryFile(delete=False, suffix='.wav') as temp_audio_file:
                temp_audio_path = temp_audio_file.name
                clip.audio.write_audiofile(temp_audio_path, codec='pcm_s16le')
        elif file_extension in ['.m4a', '.mp3', '.wav']:
            audio = AudioSegment.from_file(temp_file_path)
            total_seconds = len(audio) // 1000
            duration = f"{total_seconds // 60} мин {total_seconds % 60} сек"
            file_instance.duration = duration
            file_instance.save()

            temp_audio_path = temp_file_path  # Аудиофайлы отправляются как есть

        # Проверка существования файла перед транскрипцией
        if not os.path.exists(temp_audio_path):
            logger.error(f"Файл для транскрипции не найден: {temp_audio_path}")
            return

        # Определение MIME-типа в зависимости от формата
        mime_types = {
            '.mp4': 'video/mp4',
            '.m4a': 'audio/mp4',
            '.mp3': 'audio/mpeg',
            '.wav': 'audio/wav',
        }
        mime_type = mime_types.get(file_extension, 'application/octet-stream')

        # Отправка на транскрипцию
        with open(temp_audio_path, 'rb') as audio_file:
            audio_bytes = io.BytesIO(audio_file.read())

        logger.info(f"Отправка файла {file_path} с MIME-типом: {mime_type}")
        response = requests.post(
            'http://94.130.54.172:8040/transcribe',
            files={'audio': (file_path, audio_bytes, mime_type)}
        )

        if response.status_code == 200:
            file_instance.status = 'completed'
            transcription = response.json()
            logger.info(f"Получена транскрипция: {transcription}")
            file_instance.transcription = transcription

            # Анализ текста, если требуется
            if analyze_text:
                logger.info(f"Отправка транскрипции на анализ: {transcription}")
                analysis_response = requests.get(
                    'http://83.149.227.104/process_text',
                    params={'text': transcription}
                )
                if analysis_response.status_code == 200:
                    file_instance.analysis_result = analysis_response.json()
                else:
                    logger.error(f"Ошибка при анализе текста: {analysis_response.text}")
            file_instance.save()
        else:
            file_instance.status = 'error'
            logger.error(f"Ошибка при транскрипции: {response.text}")

        # Очистка временных файлов
        os.remove(temp_file_path)
        if file_extension in ['.mp4']:
            os.remove(temp_audio_path)

        logger.info(f"Завершение задачи process_file для файла с ID: {file_id}")

    except Exception as e:
        logger.error(f"Ошибка при обработке файла: {e}")
        file_instance.status = 'error'
        file_instance.save()

