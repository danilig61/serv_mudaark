from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


@shared_task
def send_verification_email(email, confirmation_code):
    logger.info(f"Starting send_verification_email task for email: {email}")
    try:
        send_mail(
            'Confirm your email',
            f'Your confirmation code is {confirmation_code}',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )
        logger.info(f"Verification email sent to: {email}")
    except Exception as e:
        logger.error(f"Error sending verification email: {e}")