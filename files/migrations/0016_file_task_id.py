# Generated by Django 5.1.3 on 2024-11-27 18:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('files', '0015_alter_file_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='file',
            name='task_id',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]