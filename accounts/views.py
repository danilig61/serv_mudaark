import logging
import random

from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.parsers import FormParser
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status, viewsets
from drf_yasg.utils import swagger_auto_schema
from rest_framework_simplejwt.tokens import RefreshToken

from mudaark import settings
from .serializers import UserSerializer, LoginSerializer, SetPasswordSerializer, VerifyEmailSerializer, \
    RegisterSerializer, ResendVerificationCodeSerializer
from .models import UserProfile
from .tasks import send_verification_email
from django.contrib.auth import login
from rest_framework.response import Response
from rest_framework.views import APIView
from social_django.utils import load_strategy, load_backend
from social_core.exceptions import MissingBackend, AuthException

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


class GoogleLoginAPIView(APIView):
    def get(self, request):
        try:
            # Создаем OAuth2 backend
            strategy = load_strategy(request)
            backend = load_backend(strategy, "google-oauth2",
                                   redirect_uri=settings.SOCIAL_AUTH_GOOGLE_OAUTH2_REDIRECT_URI)

            # Генерируем ссылку на авторизацию
            authorization_url = backend.auth_url()
            return Response({
                'status_code': 200,
                'authorization_url': authorization_url
            })
        except MissingBackend:
            return Response({
                'status_code': 400,
                'error': 'Missing authentication backend'
            })


class GoogleCallbackAPIView(APIView):
    parser_classes = [FormParser]  # Укажите, что используется FormParser

    def post(self, request):
        code = request.data.get('code')  # Получаем код из тела запроса
        if not code:
            return Response({'error': 'Authorization code is required'}, status=400)

        try:
            strategy = load_strategy(request)
            backend = load_backend(strategy, 'google-oauth2',
                                   redirect_uri=settings.SOCIAL_AUTH_GOOGLE_OAUTH2_REDIRECT_URI)

            # Обмениваем код на токен и получаем пользователя
            user = backend.do_auth(code)

            if user:
                # Генерация JWT токенов
                refresh = RefreshToken.for_user(user)
                return Response({
                    'status_code': 200,
                    'message': 'Authentication successful',
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                })
            else:
                return Response({'error': 'Authentication failed'}, status=400)
        except AuthException as e:
            return Response({'error': str(e)}, status=400)


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
