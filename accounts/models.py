import jwt
from attrs import define
from django.db import models
from django.contrib.auth.models import User
from typing import Dict


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    verification_code = models.CharField(max_length=6, blank=True, null=True, verbose_name='Код верификации')
    google_id = models.CharField(max_length=255, blank=True, null=True, verbose_name='Google ID')

    def __str__(self):
        return self.user.email

