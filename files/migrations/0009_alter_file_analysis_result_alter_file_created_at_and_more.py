# Generated by Django 5.1.3 on 2024-11-20 18:43

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('files', '0008_alter_file_analysis_result_alter_file_created_at_and_more'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterField(
            model_name='file',
            name='analysis_result',
            field=models.JSONField(blank=True, null=True, verbose_name='Результат анализа'),
        ),
        migrations.AlterField(
            model_name='file',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, verbose_name='Дата создания'),
        ),
        migrations.AlterField(
            model_name='file',
            name='language',
            field=models.CharField(max_length=50, verbose_name='Язык'),
        ),
        migrations.AlterField(
            model_name='file',
            name='speakers',
            field=models.IntegerField(verbose_name='Количество спикеров'),
        ),
        migrations.AlterField(
            model_name='file',
            name='transcription',
            field=models.TextField(blank=True, null=True, verbose_name='Транскрипция'),
        ),
        migrations.AlterField(
            model_name='file',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, verbose_name='Пользователь'),
        ),
    ]
