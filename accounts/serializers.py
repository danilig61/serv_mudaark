from rest_framework import serializers
from django.contrib.auth.models import User

from accounts.models import UserProfile


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        UserProfile.objects.create(user=user)
        return user

    def update(self, instance, validated_data):
        instance.email = validated_data.get('email', instance.email)
        instance.save()
        return instance


class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def create(self, validated_data):
        email = validated_data['email']
        user = User.objects.create_user(username=email, email=email, is_active=False)
        UserProfile.objects.create(user=user)
        return user



class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    refresh = serializers.CharField(write_only=True, required=False)


class VerifyEmailSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=6)


class SetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)


# class ResendVerificationCodeSerializer(serializers.Serializer):
#     email = serializers.EmailField()
