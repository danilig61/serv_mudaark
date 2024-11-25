import logging
from django.http import JsonResponse, HttpResponse, StreamingHttpResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status, viewsets
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from .serializers import UserSerializer, LoginSerializer, SetPasswordSerializer, VerifyEmailSerializer, \
    RegisterSerializer
from .models import UserProfile
from .tasks import send_verification_email
import secrets
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

logger = logging.getLogger(__name__)

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

@method_decorator(csrf_exempt, name='dispatch')
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
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            logger.info(f"Login attempt with email: {email}")
            user = authenticate(request, username=email, password=password)
            if user is not None:
                login(request, user)
                logger.info(f"Login successful for user: {user.username}")
                return Response({'message': 'Login successful', 'status_code': status.HTTP_200_OK}, status=status.HTTP_200_OK)
            else:
                logger.warning(f"Invalid credentials for email: {email}")
                return Response({'error': 'Invalid credentials', 'status_code': status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)
        return Response({'errors': serializer.errors, 'status_code': status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)

@method_decorator(csrf_exempt, name='dispatch')
class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Logout the current user",
        responses={200: "Logout successful"},
    )
    def post(self, request):
        logout(request)
        return Response({'message': 'Logout successful', 'status_code': status.HTTP_200_OK}, status=status.HTTP_200_OK)

@method_decorator(csrf_exempt, name='dispatch')
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
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            if User.objects.filter(email=email).exists():
                return Response({'error': 'User with this email already exists', 'status_code': status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)
            confirmation_code = secrets.token_hex(3)
            request.session['confirmation_code'] = confirmation_code
            request.session['email'] = email
            send_verification_email.delay(email, confirmation_code)
            return Response({'message': 'Verification email sent', 'status_code': status.HTTP_200_OK}, status=status.HTTP_200_OK)
        return Response({'errors': serializer.errors, 'status_code': status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)

@method_decorator(csrf_exempt, name='dispatch')
class VerifyEmailAPIView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Verify the email with a confirmation code",
        request_body=VerifyEmailSerializer,
        responses={
            200: "Email verified successfully",
            400: "Invalid confirmation code",
        },
    )
    def post(self, request):
        serializer = VerifyEmailSerializer(data=request.data)
        if serializer.is_valid():
            code = serializer.validated_data['code']
            if code == request.session.get('confirmation_code'):
                return Response({'message': 'Email verified successfully', 'status_code': status.HTTP_200_OK}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid confirmation code', 'status_code': status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)
        return Response({'errors': serializer.errors, 'status_code': status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)

@method_decorator(csrf_exempt, name='dispatch')
class SetPasswordAPIView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Set a password for the user",
        request_body=SetPasswordSerializer,
        responses={
            200: "Password set successfully",
            400: "Passwords do not match",
        },
    )
    def post(self, request):
        serializer = SetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            password = serializer.validated_data['password']
            confirm_password = serializer.validated_data['confirm_password']
            if password == confirm_password:
                email = request.session.get('email')
                user = User.objects.create_user(email, email, password)
                UserProfile.objects.create(user=user)
                return Response({'message': 'Password set successfully', 'status_code': status.HTTP_200_OK}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Passwords do not match', 'status_code': status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)
        return Response({'errors': serializer.errors, 'status_code': status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)

@method_decorator(csrf_exempt, name='dispatch')
class MainAPIView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Get the main welcome page",
        responses={200: "Main welcome page"},
    )
    def get(self, request):
        if request.user.is_authenticated:
            return Response({'message': f'Welcome, {request.user.username}', 'status_code': status.HTTP_200_OK}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Welcome to the main page', 'status_code': status.HTTP_200_OK}, status=status.HTTP_200_OK)
