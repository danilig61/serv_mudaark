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

logger = logging.getLogger(__name__)

@shared_task
def process_file(file_id, file_path, analyze_text):
    logger.info(f"Starting process_file task for file ID: {file_id}")
    try:
        file_instance = File.objects.get(id=file_id)
        file_instance.status = 'processing'
        file_instance.save()

        # Скачиваем файл из MinIO во временную директорию
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            minio_client.fget_object(
                settings.AWS_STORAGE_BUCKET_NAME,
                file_path,
                temp_file.name
            )
            temp_file_path = temp_file.name

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

        # Удаление временного файла
        os.remove(temp_file_path)
        os.remove(temp_audio_path)
        logger.info(f"Finished process_file task for file ID: {file_id}")
    except Exception as e:
        file_instance.status = 'error'
        logger.error(f"Error processing file: {e}")
        file_instance.save()
