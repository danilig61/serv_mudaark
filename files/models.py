from django.db import models
from django.contrib.auth.models import User


class File(models.Model):
    STATUS_CHOICES = [
        ('processing', 'В процессе'),
        ('completed', 'Обработан'),
        ('error', 'Ошибка'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name='Пользователь')
    file = models.FileField(verbose_name='Файл')
    name = models.CharField(max_length=100, verbose_name='Имя файла')
    speakers = models.IntegerField(verbose_name='Количество спикеров')
    language = models.CharField(max_length=50, verbose_name='Язык')
    duration = models.CharField(max_length=50, blank=True, null=True, verbose_name='Длительность')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='Дата создания')
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='processing', verbose_name='Статус')
    transcription = models.TextField(blank=True, null=True, verbose_name='Транскрипция')
    analysis_result = models.JSONField(blank=True, null=True, verbose_name='Результат анализа')
    task_id = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        return self.name
