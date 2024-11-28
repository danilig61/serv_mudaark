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


@define
class GoogleRawLoginCredentials:
    client_id: str
    client_secret: str
    project_id: str

@define
class GoogleAccessTokens:
    id_token: str
    access_token: str

    def decode_id_token(self) -> Dict[str, str]:
        id_token = self.id_token
        decoded_token = jwt.decode(jwt=id_token, options={"verify_signature": False})
        return decoded_token