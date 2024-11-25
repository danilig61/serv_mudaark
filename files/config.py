import logging
from minio import Minio
from django.conf import settings

# Настройка логирования
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler = logging.FileHandler('app.log')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Инициализация клиента MinIO
minio_client = Minio(
    'minio:9000',
    access_key=settings.AWS_ACCESS_KEY_ID,
    secret_key=settings.AWS_SECRET_ACCESS_KEY,
    secure=False
)

# Проверка наличия бакета
if not minio_client.bucket_exists(settings.AWS_STORAGE_BUCKET_NAME):
    minio_client.make_bucket(settings.AWS_STORAGE_BUCKET_NAME)
    logger.info(f"Bucket {settings.AWS_STORAGE_BUCKET_NAME} created.")
else:
    logger.info(f"Bucket {settings.AWS_STORAGE_BUCKET_NAME} already exists.")
