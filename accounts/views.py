import logging
import random

from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status, viewsets
from drf_yasg.utils import swagger_auto_schema
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserSerializer, LoginSerializer, SetPasswordSerializer, VerifyEmailSerializer, \
    RegisterSerializer
from .models import UserProfile
from .tasks import send_verification_email
import secrets

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
        responses={200: "Logout successful", 401: "Unauthorized"},
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


class RegisterAPIView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Register a new user",
        request_body=RegisterSerializer,
        responses={
            200: "Verification email sent",
            400: "User with this email already exists or invalid data",
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
            confirmation_code = str(random.randint(100000, 999999))  # Generate a 6-digit numeric code
            request.session['confirmation_code'] = confirmation_code
            request.session['email'] = email
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
        },
    )
    def post(self, request):
        logger.info("Starting VerifyEmailAPIView post method")
        serializer = VerifyEmailSerializer(data=request.data)
        if serializer.is_valid():
            code = serializer.validated_data['code']
            stored_code = request.session.get('confirmation_code')
            stored_email = request.session.get('email')
            if stored_code and stored_email and code == stored_code:
                user, created = User.objects.get_or_create(email=stored_email)
                if created:
                    user.is_active = False
                    user.save()
                logger.info(f"Email {stored_email} verified successfully")
                return Response({
                    'status_code': status.HTTP_200_OK,
                    'message': 'Email verified successfully',
                }, status=status.HTTP_200_OK)
            else:
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
        },
    )
    def post(self, request):
        logger.info("Starting SetPasswordAPIView post method")
        serializer = SetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            password = serializer.validated_data['password']
            confirm_password = serializer.validated_data['confirm_password']
            if password != confirm_password:
                return Response({
                    'status_code': status.HTTP_400_BAD_REQUEST,
                    'error': 'Passwords do not match',
                }, status=status.HTTP_400_BAD_REQUEST)
            email = request.session.get('email')
            if email:
                user = User.objects.get(email=email)
                user.set_password(password)
                user.is_active = True
                user.save()
                logger.info(f"Password set successfully for user: {email}")
                return Response({
                    'status_code': status.HTTP_200_OK,
                    'message': 'Password set successfully',
                }, status=status.HTTP_200_OK)
            else:
                logger.warning(f"Email not found in session")
                return Response({
                    'status_code': status.HTTP_400_BAD_REQUEST,
                    'error': 'User not found',
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
        responses={200: "Main welcome page"},
    )
    def get(self, request):
        logger.info("Starting MainAPIView get method")
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
