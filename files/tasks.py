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
        file_instance = File.objects.get(id=file_id)
        file_instance.status = 'processing'
        file_instance.save()

        # Проверка существования файла перед началом обработки
        if not File.objects.filter(id=file_id).exists():
            logger.info(f"Файл {file_id} был удален. Остановка задачи.")
            return

        # Скачиваем файл из MinIO во временную директорию
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            minio_client.fget_object(
                settings.AWS_STORAGE_BUCKET_NAME,
                file_path,
                temp_file.name
            )
            temp_file_path = temp_file.name

        # Проверка существования файла перед обработкой видео
        if not File.objects.filter(id=file_id).exists():
            logger.info(f"Файл {file_id} был удален. Остановка задачи.")
            os.remove(temp_file_path)
            return

        file_extension = os.path.splitext(file_path)[1].lower()
        if file_extension in ['.mp4']:
            # Обработка видеофайла
            clip = mp.VideoFileClip(temp_file_path)
            total_seconds = int(clip.duration)
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            duration = f"{minutes} мин {seconds} сек"
            file_instance.duration = duration
            file_instance.save()

            # Извлечение аудиодорожки в байты
            with tempfile.NamedTemporaryFile(delete=False, suffix='.wav') as temp_audio_file:
                temp_audio_path = temp_audio_file.name
                clip.audio.write_audiofile(temp_audio_path, codec='pcm_s16le')
        elif file_extension in ['.m4a', '.mp3', '.wav']:
            # Обработка аудиофайла
            audio = AudioSegment.from_file(temp_file_path)
            total_seconds = len(audio) // 1000
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            duration = f"{minutes} мин {seconds} сек"
            file_instance.duration = duration
            file_instance.save()

            # Сохранение аудиофайла во временный файл
            temp_audio_path = temp_file_path

        # Проверка существования файла перед отправкой на транскрипцию
        if not File.objects.filter(id=file_id).exists():
            logger.info(f"Файл {file_id} был удален. Остановка задачи.")
            os.remove(temp_file_path)
            if file_extension in ['.m4a', '.mp3', '.wav']:
                os.remove(temp_audio_path)
            return

        with open(temp_audio_path, 'rb') as audio_file:
            audio_bytes = io.BytesIO(audio_file.read())

        logger.info(f"Отправка файла {file_path} на транскрипцию")
        response = requests.post(
            'http://94.130.54.172:8040/transcribe',
            files={'audio': ('audio.wav', audio_bytes, 'audio/wav')}
        )
        if response.status_code == 200:
            file_instance.status = 'completed'
            transcription = response.json()
            logger.info(f"Получена транскрипция: {transcription}")
            file_instance.transcription = transcription

            if analyze_text:
                logger.info(f"Отправка транскрипции на анализ: {transcription}")
                analysis_response = requests.get('http://83.149.227.104/process_text', params={'text': transcription})
                if analysis_response.status_code == 200:
                    file_instance.analysis_result = analysis_response.json()
                else:
                    logger.error(f"Ошибка при анализе текста: {analysis_response.text}")
            file_instance.save()
        else:
            file_instance.status = 'error'
            logger.error(f"Ошибка при транскрипции: {response.text}")
        file_instance.save()

        # Удаление временного файла
        os.remove(temp_file_path)
        if file_extension in ['.m4a', '.mp3', '.wav']:
            os.remove(temp_audio_path)
        logger.info(f"Завершение задачи process_file для файла с ID: {file_id}")
    except Exception as e:
        file_instance.status = 'error'
        logger.error(f"Ошибка при обработке файла: {e}")
        file_instance.save()


