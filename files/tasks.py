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

logger = logging.getLogger(__name__)


@shared_task(bind=True)
def process_file(self, file_id, file_path, analyze_text):
    logger.info(f"Starting process_file task for file ID: {file_id}")
    try:
        file_instance = File.objects.get(id=file_id)
        file_instance.status = 'processing'
        file_instance.save()

        # Проверка существования файла перед началом обработки
        if not File.objects.filter(id=file_id).exists():
            logger.info(f"File {file_id} has been deleted. Stopping task.")
            return

        # Скачиваем файл из MinIO во временную директорию
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            minio_client.fget_object(
                settings.AWS_STORAGE_BUCKET_NAME,
                file_path,
                temp_file.name
            )
            temp_file_path = temp_file.name

        # Проверка формата файла
        file_extension = os.path.splitext(file_path)[1].lower()
        supported_video_formats = ['.mp4']
        supported_audio_formats = ['.m4a', '.mp3', '.wav']

        if file_extension in supported_video_formats:
            # Обработка видеофайлов
            clip = mp.VideoFileClip(temp_file_path)
            total_seconds = int(clip.duration)
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            duration = f"{minutes} мин {seconds} сек"
            file_instance.duration = duration

            # Извлечение аудиодорожки
            with tempfile.NamedTemporaryFile(delete=False, suffix='.wav') as temp_audio_file:
                temp_audio_path = temp_audio_file.name
                clip.audio.write_audiofile(temp_audio_path, codec='pcm_s16le')

        elif file_extension in supported_audio_formats:
            # Обработка аудиофайлов
            audio = AudioSegment.from_file(temp_file_path)
            total_seconds = len(audio) // 1000  # Длительность в секундах
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            duration = f"{minutes} мин {seconds} сек"
            file_instance.duration = duration

            # Конвертация в WAV
            with tempfile.NamedTemporaryFile(delete=False, suffix='.wav') as temp_audio_file:
                temp_audio_path = temp_audio_file.name
                audio.export(temp_audio_path, format='wav')

        else:
            # Если формат файла не поддерживается
            logger.error(f"Unsupported file format: {file_extension}")
            file_instance.status = 'error'
            file_instance.error_message = f"Unsupported file format: {file_extension}"
            file_instance.save()
            os.remove(temp_file_path)
            return

        # Проверка существования файла перед отправкой на транскрипцию
        if not File.objects.filter(id=file_id).exists():
            logger.info(f"File {file_id} has been deleted. Stopping task.")
            os.remove(temp_file_path)
            os.remove(temp_audio_path)
            return

        # Отправка аудиофайла на транскрипцию
        with open(temp_audio_path, 'rb') as audio_file:
            audio_bytes = io.BytesIO(audio_file.read())

        logger.info(f"Sending file {file_path} for transcription")
        response = requests.post(
            'http://94.130.54.172:8040/transcribe',
            files={'audio': ('audio.wav', audio_bytes, 'audio/wav')}
        )
        if response.status_code == 200:
            file_instance.status = 'completed'
            transcription = response.json()
            logger.info(f"Received transcription: {transcription}")
            file_instance.transcription = transcription

            if analyze_text:
                logger.info(f"Sending transcription for analysis: {transcription}")
                analysis_response = requests.get('http://83.149.227.104/process_text', params={'text': transcription})
                if analysis_response.status_code == 200:
                    file_instance.analysis_result = analysis_response.json()
                else:
                    logger.error(f"Error during text analysis: {analysis_response.text}")
            file_instance.save()
        else:
            file_instance.status = 'error'
            logger.error(f"Error during transcription: {response.text}")
        file_instance.save()

        # Удаление временных файлов
        os.remove(temp_file_path)
        os.remove(temp_audio_path)
        logger.info(f"Finished process_file task for file ID: {file_id}")
    except Exception as e:
        file_instance.status = 'error'
        logger.error(f"Error processing file: {e}")
        file_instance.save()
