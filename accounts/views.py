import random
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status, viewsets
from drf_yasg.utils import swagger_auto_schema
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserSerializer, LoginSerializer, SetPasswordSerializer, VerifyEmailSerializer, \
    RegisterSerializer, ResendVerificationCodeSerializer, ResetPasswordSerializer
from .models import UserProfile
from .tasks import send_verification_email
from rest_framework.views import APIView
from rest_framework.response import Response
import logging
from django.conf import settings
import requests


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
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        try:
            logger.info("Starting SocialLoginAPIView post method")

            access_token = request.data.get("access_token")
            if not access_token:
                logger.error("Access token is required")
                return Response({
                    'status_code': status.HTTP_400_BAD_REQUEST,
                    'error': 'Access token is required',
                }, status=status.HTTP_400_BAD_REQUEST)

            google_token_info_url = "https://www.googleapis.com/oauth2/v1/tokeninfo"
            response = requests.get(google_token_info_url, params={"access_token": access_token})

            if response.status_code != 200:
                logger.error("Invalid token received from Google API")
                return Response({
                    'status_code': status.HTTP_400_BAD_REQUEST,
                    'error': 'Invalid token',
                }, status=status.HTTP_400_BAD_REQUEST)

            idinfo = response.json()
            if idinfo.get("audience") != settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY:
                logger.error("Token audience mismatch")
                return Response({
                    'status_code': status.HTTP_400_BAD_REQUEST,
                    'error': 'Invalid token audience',
                }, status=status.HTTP_400_BAD_REQUEST)

            email = idinfo.get('email')
            if not email:
                logger.error("Email not found in token info")
                return Response({
                    'status_code': status.HTTP_400_BAD_REQUEST,
                    'error': 'Email not found in token',
                }, status=status.HTTP_400_BAD_REQUEST)

            try:
                user, created = User.objects.get_or_create(
                    email=email,
                    defaults={
                        "username": email.split("@")[0],
                        "first_name": idinfo.get("given_name", ""),
                        "last_name": idinfo.get("family_name", ""),
                    },
                )
                if created:
                    logger.info(f"New user created: {user.email}")
            except Exception as e:
                logger.error(f"Error creating user: {e}")
                return Response({
                    'status_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                    'error': 'Could not create user',
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            refresh = RefreshToken.for_user(user)
            logger.info("Tokens generated successfully")

            return Response({
                "status_code": status.HTTP_200_OK,
                "message": "Login successful",
                "tokens": {
                    "access": str(refresh.access_token),
                    "refresh": str(refresh),
                },
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "name": user.get_full_name(),
                },
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Internal Server Error: {e}")
            return Response({
                'status_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'error': 'Internal Server Error',
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class YandexLoginAPIView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        try:
            logger.info("Starting YandexLoginAPIView post method")

            access_token = request.data.get("access_token")
            state = request.data.get("state")
            if not access_token or not state:
                logger.error("Access token and state are required")
                return Response({
                    'status_code': status.HTTP_400_BAD_REQUEST,
                    'error': 'Access token and state are required',
                }, status=status.HTTP_400_BAD_REQUEST)

            logger.info("Access token and state received, verifying with Yandex")

            yandex_token_info_url = "https://login.yandex.ru/info"
            response = requests.get(yandex_token_info_url, headers={
                "Authorization": f"OAuth {access_token}"
            })

            if response.status_code != 200:
                logger.error("Invalid token received from Yandex API")
                return Response({
                    'status_code': status.HTTP_400_BAD_REQUEST,
                    'error': 'Invalid token',
                }, status=status.HTTP_400_BAD_REQUEST)

            user_info = response.json()
            logger.info(f"Yandex API user info: {user_info}")

            email = user_info.get('default_email')
            if not email:
                logger.error("Email not found in Yandex user info")
                return Response({
                    'status_code': status.HTTP_400_BAD_REQUEST,
                    'error': 'Email not found in Yandex user info',
                }, status=status.HTTP_400_BAD_REQUEST)

            first_name = user_info.get('first_name', '')
            last_name = user_info.get('last_name', '')

            try:
                user, created = User.objects.get_or_create(
                    email=email,
                    defaults={
                        "username": email.split("@")[0],
                        "first_name": first_name,
                        "last_name": last_name,
                    },
                )
                if created:
                    logger.info(f"New user created: {user.email}")
            except Exception as e:
                logger.error(f"Error creating user: {e}")
                return Response({
                    'status_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                    'error': 'Could not create user',
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            refresh = RefreshToken.for_user(user)
            logger.info("Tokens generated successfully")

            return Response({
                "status_code": status.HTTP_200_OK,
                "message": "Login successful",
                "tokens": {
                    "access": str(refresh.access_token),
                    "refresh": str(refresh),
                },
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "name": user.get_full_name(),
                },
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Internal Server Error: {e}")
            return Response({
                'status_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'error': 'Internal Server Error',
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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


class ForgotPasswordAPIView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Request password reset by email",
        request_body=ResendVerificationCodeSerializer,
        responses={
            200: "Verification email sent",
            400: "User not found or invalid data",
            500: "Internal Server Error",
        },
    )
    def post(self, request):
        logger.info("Starting ForgotPasswordAPIView post method")
        serializer = ResendVerificationCodeSerializer(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user_profile = UserProfile.objects.get(user__email=email)
                confirmation_code = str(random.randint(100000, 999999))  # Генерация 6-значного кода
                user_profile.verification_code = confirmation_code
                user_profile.save()

                # Отправка кода подтверждения на email
                send_verification_email.delay(email, confirmation_code)
                logger.info(f"Verification code sent to {email}")
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


class VerifyForgotPasswordCodeAPIView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Verify the reset code sent to user's email",
        request_body=VerifyEmailSerializer,
        responses={
            200: "Code verified successfully",
            400: "Invalid confirmation code",
            500: "Internal Server Error",
        },
    )
    def post(self, request):
        logger.info("Starting VerifyForgotPasswordCodeAPIView post method")
        serializer = VerifyEmailSerializer(data=request.data)

        if serializer.is_valid():
            code = serializer.validated_data['code']
            try:
                user_profile = UserProfile.objects.get(verification_code=code)
                user = user_profile.user
                logger.info(f"Code verified successfully for user: {user.email}")
                return Response({
                    'status_code': status.HTTP_200_OK,
                    'message': 'Code verified successfully. You can now reset your password.',
                    'user_id': user.id,  # Возвращаем user_id для дальнейшей привязки при смене пароля
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


class ResetPasswordAPIView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Set a new password for the user",
        request_body=ResetPasswordSerializer,
        responses={
            200: "Password reset successfully",
            400: "Invalid data or code verification failed",
            500: "Internal Server Error",
        },
    )
    def post(self, request):
        logger.info("Starting ResetPasswordAPIView post method")
        serializer = ResetPasswordSerializer(data=request.data)

        if serializer.is_valid():
            password = serializer.validated_data['password']
            confirm_password = serializer.validated_data['confirm_password']
            user_id = serializer.validated_data.get('user_id')  # Получаем user_id

            # Проверка совпадения паролей
            if password != confirm_password:
                return Response({
                    'status_code': status.HTTP_400_BAD_REQUEST,
                    'error': 'Passwords do not match',
                }, status=status.HTTP_400_BAD_REQUEST)

            if user_id:
                try:
                    user = User.objects.get(id=user_id)

                    # Сброс пароля
                    user.set_password(password)
                    user.save()

                    logger.info(f"Password reset successfully for user: {user.email}")
                    return Response({
                        'status_code': status.HTTP_200_OK,
                        'message': 'Password reset successfully',
                    }, status=status.HTTP_200_OK)

                except User.DoesNotExist:
                    logger.warning(f"User with ID {user_id} not found")
                    return Response({
                        'status_code': status.HTTP_400_BAD_REQUEST,
                        'error': 'User not found',
                    }, status=status.HTTP_400_BAD_REQUEST)

        logger.error(f"Validation errors: {serializer.errors}")
        return Response({
            'status_code': status.HTTP_400_BAD_REQUEST,
            'errors': serializer.errors,
        }, status=status.HTTP_400_BAD_REQUEST)

