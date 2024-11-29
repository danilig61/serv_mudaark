import logging
import random

from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status, viewsets
from drf_yasg.utils import swagger_auto_schema
from rest_framework_simplejwt.tokens import RefreshToken
from social_django.utils import load_backend, load_strategy

from .serializers import UserSerializer, LoginSerializer, SetPasswordSerializer, VerifyEmailSerializer, \
    RegisterSerializer, ResendVerificationCodeSerializer
from .models import UserProfile
from .tasks import send_verification_email
from rest_framework.views import APIView
from rest_framework.response import Response
import logging
import requests
from django.contrib.auth import login

logger = logging.getLogger(__name__)


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer


class LoginAPIView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Login a user with email and password",
        request_body=LoginSerializer,
        responses={
            200: "Login successful",
            400: "Invalid credentials",
            500: "Internal Server Error",
        },
    )
    def post(self, request):
        logger.info("Starting LoginAPIView post method")
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            logger.info(f"Login attempt with email: {email}")
            user = authenticate(request, username=email, password=password)
            if user is not None:
                refresh = RefreshToken.for_user(user)
                logger.info(f"Login successful for user: {email}")
                return Response({
                    'status_code': status.HTTP_200_OK,
                    'message': 'Login successful',
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                }, status=status.HTTP_200_OK)
            else:
                logger.warning(f"Invalid credentials for email: {email}")
                return Response({
                    'status_code': status.HTTP_400_BAD_REQUEST,
                    'error': 'Invalid credentials',
                }, status=status.HTTP_400_BAD_REQUEST)
        logger.error(f"Validation errors: {serializer.errors}")
        return Response({
            'status_code': status.HTTP_400_BAD_REQUEST,
            'errors': serializer.errors,
        }, status=status.HTTP_400_BAD_REQUEST)


class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Logout the current user",
        request_body=LoginSerializer,
        responses={200: "Logout successful", 401: "Unauthorized", 500: "Internal Server Error"},
    )
    def post(self, request):
        try:
            logger.info("Starting LogoutAPIView post method")
            refresh_token = request.data.get("refresh")
            if refresh_token:
                try:
                    token = RefreshToken(refresh_token)
                    token.blacklist()
                    logger.info(f"Logout successful for user: {request.user.email}")
                    return Response({
                        'status_code': status.HTTP_200_OK,
                        'message': 'Logout successful',
                    }, status=status.HTTP_200_OK)
                except Exception as e:
                    logger.error(f"Error during logout: {e}")
                    return Response({
                        'status_code': status.HTTP_400_BAD_REQUEST,
                        'error': 'Invalid refresh token',
                    }, status=status.HTTP_400_BAD_REQUEST)
            logger.error("Refresh token is required")
            return Response({
                'status_code': status.HTTP_400_BAD_REQUEST,
                'error': 'Refresh token is required',
            }, status=status.HTTP_400_BAD_REQUEST)
        except AuthenticationFailed as e:
            logger.error(f"Authentication failed: {e}")
            return Response({
                'status_code': status.HTTP_401_UNAUTHORIZED,
                'error': 'Unauthorized',
            }, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            logger.error(f"Internal Server Error: {e}")
            return Response({
                'status_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'error': 'Internal Server Error',
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RegisterAPIView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Register a new user",
        request_body=RegisterSerializer,
        responses={
            200: "Verification email sent",
            400: "User with this email already exists or invalid data",
            500: "Internal Server Error",
        },
    )
    def post(self, request):
        logger.info("Starting RegisterAPIView post method")
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            if User.objects.filter(email=email).exists():
                logger.warning(f"User with email {email} already exists")
                return Response({
                    'status_code': status.HTTP_400_BAD_REQUEST,
                    'error': 'User with this email already exists',
                }, status=status.HTTP_400_BAD_REQUEST)
            user = serializer.save()
            confirmation_code = str(random.randint(100000, 999999))  # Generate a 6-digit numeric code
            user_profile, created = UserProfile.objects.get_or_create(user=user)
            user_profile.verification_code = confirmation_code
            user_profile.save()
            send_verification_email.delay(email, confirmation_code)
            logger.info(f"Verification email sent to: {email}")
            return Response({
                'status_code': status.HTTP_200_OK,
                'message': 'Verification email sent',
            }, status=status.HTTP_200_OK)
        logger.error(f"Validation errors: {serializer.errors}")
        return Response({
            'status_code': status.HTTP_400_BAD_REQUEST,
            'errors': serializer.errors,
        }, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmailAPIView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Verify email with confirmation code",
        request_body=VerifyEmailSerializer,
        responses={
            200: "Email verified successfully",
            400: "Invalid confirmation code",
            500: "Internal Server Error",
        },
    )
    def post(self, request):
        logger.info("Starting VerifyEmailAPIView post method")
        serializer = VerifyEmailSerializer(data=request.data)
        if serializer.is_valid():
            code = serializer.validated_data['code']
            try:
                user_profile = UserProfile.objects.get(verification_code=code)
                user = user_profile.user
                user.is_active = True
                user.save()
                user_profile.verification_code = None  # Clear the verification code
                user_profile.save()
                logger.info(f"Email verified successfully for user: {user.email}")
                return Response({
                    'status_code': status.HTTP_200_OK,
                    'message': 'Email verified successfully',
                }, status=status.HTTP_200_OK)
            except UserProfile.DoesNotExist:
                logger.warning(f"Invalid confirmation code: {code}")
                return Response({
                    'status_code': status.HTTP_400_BAD_REQUEST,
                    'error': 'Invalid confirmation code',
                }, status=status.HTTP_400_BAD_REQUEST)
        logger.error(f"Validation errors: {serializer.errors}")
        return Response({
            'status_code': status.HTTP_400_BAD_REQUEST,
            'errors': serializer.errors,
        }, status=status.HTTP_400_BAD_REQUEST)


class SetPasswordAPIView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Set password for the user",
        request_body=SetPasswordSerializer,
        responses={
            200: "Password set successfully",
            400: "Invalid data or user not found",
            500: "Internal Server Error",
        },
    )
    def post(self, request):
        logger.info("Starting SetPasswordAPIView post method")
        serializer = SetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            password = serializer.validated_data['password']
            confirm_password = serializer.validated_data['confirm_password']
            email = serializer.validated_data.get('email')  # Get email from request data
            if password != confirm_password:
                return Response({
                    'status_code': status.HTTP_400_BAD_REQUEST,
                    'error': 'Passwords do not match',
                }, status=status.HTTP_400_BAD_REQUEST)
            if email:
                try:
                    user = User.objects.get(email=email)
                    user.set_password(password)
                    user.save()
                    logger.info(f"Password set successfully for user: {email}")
                    return Response({
                        'status_code': status.HTTP_200_OK,
                        'message': 'Password set successfully',
                    }, status=status.HTTP_200_OK)
                except User.DoesNotExist:
                    logger.warning(f"User with email {email} not found")
                    return Response({
                        'status_code': status.HTTP_400_BAD_REQUEST,
                        'error': 'User not found',
                    }, status=status.HTTP_400_BAD_REQUEST)
            else:
                logger.warning("Email not provided in request")
                return Response({
                    'status_code': status.HTTP_400_BAD_REQUEST,
                    'error': 'Email is required',
                }, status=status.HTTP_400_BAD_REQUEST)
        logger.error(f"Validation errors: {serializer.errors}")
        return Response({
            'status_code': status.HTTP_400_BAD_REQUEST,
            'errors': serializer.errors,
        }, status=status.HTTP_400_BAD_REQUEST)


class MainAPIView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Get the main welcome page",
        responses={200: "Main welcome page", 500: "Internal Server Error"},
    )
    def get(self, request):
        logger.info("Starting MainAPIView get method")
        try:
            if request.user.is_authenticated:
                logger.info(f"Welcome, {request.user.username}")
                return Response({
                    'status_code': status.HTTP_200_OK,
                    'message': f'Welcome, {request.user.username}',
                }, status=status.HTTP_200_OK)
            else:
                logger.info("Welcome to the main page")
                return Response({
                    'status_code': status.HTTP_200_OK,
                    'message': 'Welcome to the main page',
                }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Internal Server Error: {e}")
            return Response({
                'status_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'error': 'Internal Server Error',
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SocialLoginAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        logger.info("Starting SocialLoginAPIView post method")
        provider = request.data.get("provider")
        access_token = request.data.get("access_token")

        if not provider or not access_token:
            return Response({
                "status_code": status.HTTP_400_BAD_REQUEST,
                "error": "Provider and access token are required"
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Загружаем стратегию и бэкенд для выбранного провайдера (Google или Yandex)
            strategy = load_strategy(request)
            backend = load_backend(strategy, provider, redirect_uri=None)

            # Проверка на Google или Yandex
            if provider == 'google':
                user = self._authenticate_with_google(access_token)
            elif provider == 'yandex':
                user = self._authenticate_with_yandex(access_token)
            else:
                return Response({
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "error": "Unsupported provider"
                }, status=status.HTTP_400_BAD_REQUEST)

            # Если пользователь успешно авторизован, создаем JWT токены и логиним пользователя
            if user:
                login(request, user)
                refresh = RefreshToken.for_user(user)
                return Response({
                    "status_code": status.HTTP_200_OK,
                    "message": "Login successful",
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "error": "Invalid access token or user not found",
                }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error during social login: {e}")
            return Response({
                "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "error": str(e),
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _authenticate_with_google(self, access_token):
        # Получаем данные пользователя из Google
        user_info = self._get_google_user_data(access_token)
        if user_info:
            # Здесь логика для получения или создания пользователя на основе данных от Google
            # Например, создаем пользователя или находим существующего
            user = self._get_or_create_user_from_google(user_info)
            return user
        return None

    def _authenticate_with_yandex(self, access_token):
        # Получаем данные пользователя из Yandex
        user_info = self._get_yandex_user_data(access_token)
        if user_info:
            # Здесь логика для получения или создания пользователя на основе данных от Yandex
            # Например, создаем пользователя или находим существующего
            user = self._get_or_create_user_from_yandex(user_info)
            return user
        return None

    def _get_google_user_data(self, access_token):
        try:
            headers = {'Authorization': f'Bearer {access_token}'}
            response = requests.get('https://www.googleapis.com/oauth2/v3/userinfo', headers=headers)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to fetch Google user data: {response.text}")
        except Exception as e:
            logger.error(f"Error getting Google user data: {e}")
        return None

    def _get_yandex_user_data(self, access_token):
        try:
            headers = {'Authorization': f'OAuth {access_token}'}
            response = requests.get('https://login.yandex.ru/info', headers=headers)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to fetch Yandex user data: {response.text}")
        except Exception as e:
            logger.error(f"Error getting Yandex user data: {e}")
        return None

    def _get_or_create_user_from_google(self, user_info):
        # Логика для поиска или создания пользователя на основе данных от Google
        # Например, создаем пользователя, если его нет в базе
        user, created = User.objects.get_or_create(
            username=user_info['email'],  # Или любой другой параметр для идентификации
            defaults={
                'first_name': user_info.get('given_name', ''),
                'last_name': user_info.get('family_name', ''),
                'email': user_info.get('email', ''),
            }
        )
        return user

    def _get_or_create_user_from_yandex(self, user_info):
        # Логика для поиска или создания пользователя на основе данных от Yandex
        # Например, создаем пользователя, если его нет в базе
        user, created = User.objects.get_or_create(
            username=user_info['login'],  # Или любой другой параметр для идентификации
            defaults={
                'first_name': user_info.get('first_name', ''),
                'last_name': user_info.get('last_name', ''),
                'email': user_info.get('default_email', ''),
            }
        )
        return user


class ResendVerificationCodeAPIView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Resend verification code to the user's email",
        request_body=ResendVerificationCodeSerializer,
        responses={
            200: "Verification email sent",
            400: "Invalid email or user not found",
            500: "Internal Server Error",
        },
    )
    def post(self, request):
        logger.info("Starting ResendVerificationCodeAPIView post method")
        serializer = ResendVerificationCodeSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user_profile = UserProfile.objects.get(user__email=email)
                confirmation_code = str(random.randint(100000, 999999))  # Generate a 6-digit numeric code
                user_profile.verification_code = confirmation_code
                user_profile.save()
                send_verification_email.delay(email, confirmation_code)
                logger.info(f"Verification email resent to: {email}")
                return Response({
                    'status_code': status.HTTP_200_OK,
                    'message': 'Verification email sent',
                }, status=status.HTTP_200_OK)
            except UserProfile.DoesNotExist:
                logger.warning(f"User with email {email} not found")
                return Response({
                    'status_code': status.HTTP_400_BAD_REQUEST,
                    'error': 'User not found',
                }, status=status.HTTP_400_BAD_REQUEST)
        logger.error(f"Validation errors: {serializer.errors}")
        return Response({
            'status_code': status.HTTP_400_BAD_REQUEST,
            'errors': serializer.errors,
        }, status=status.HTTP_400_BAD_REQUEST)
