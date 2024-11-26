import logging
import os

from django.http import JsonResponse, HttpResponse, StreamingHttpResponse
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from django.shortcuts import get_object_or_404
from .models import File
from .serializers import FileSerializer, UploadFileSerializer
from .tasks import process_file
from .config import minio_client
import requests
from django.conf import settings
from rest_framework.parsers import MultiPartParser, FormParser

logger = logging.getLogger(__name__)


class UploadFileAPIView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    @swagger_auto_schema(
        operation_description="Upload a file or provide a URL for processing",
        request_body=UploadFileSerializer,
        responses={
            201: "File uploaded successfully",
            400: "Invalid data",
            401: "Unauthorized",
        },
    )
    def post(self, request):
        try:
            logger.info("Starting UploadFileAPIView post method")
            serializer = UploadFileSerializer(data=request.data)
            if serializer.is_valid():
                file = serializer.validated_data.get('file')
                url = serializer.validated_data.get('url')
                name = serializer.validated_data['name']
                speakers = serializer.validated_data['speakers']
                language = serializer.validated_data['language']
                analyze_text = serializer.validated_data.get('analyze_text', False)

                file_path = None
                if file:
                    file_path = file.name
                    minio_client.put_object(
                        settings.AWS_STORAGE_BUCKET_NAME,
                        file_path,
                        file,
                        file.size,
                    )
                elif url:
                    response = requests.get(url)
                    file_path = os.path.basename(url)
                    minio_client.put_object(
                        settings.AWS_STORAGE_BUCKET_NAME,
                        file_path,
                        response.content,
                        len(response.content),
                    )
                else:
                    logger.error("Please provide a file or URL")
                    return Response({
                        'status_code': status.HTTP_400_BAD_REQUEST,
                        'error': 'Please provide a file or URL',
                    }, status=status.HTTP_400_BAD_REQUEST)

                file_instance = File.objects.create(
                    user=request.user,
                    file=file_path,
                    name=name,
                    speakers=speakers,
                    language=language,
                    status='pending',
                )
                process_file.delay(file_instance.id, file_path, analyze_text)
                logger.info(f"File uploaded successfully: {file_path}")
                return Response({
                    'status_code': status.HTTP_201_CREATED,
                    'message': 'File uploaded successfully',
                }, status=status.HTTP_201_CREATED)
            logger.error(f"Validation errors: {serializer.errors}")
            return Response({
                'status_code': status.HTTP_400_BAD_REQUEST,
                'errors': serializer.errors,
            }, status=status.HTTP_400_BAD_REQUEST)
        except AuthenticationFailed as e:
            logger.error(f"Authentication failed: {e}")
            return Response({
                'status_code': status.HTTP_401_UNAUTHORIZED,
                'error': 'Unauthorized',
            }, status=status.HTTP_401_UNAUTHORIZED)


class MyFilesAPIView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get a list of files uploaded by the user",
        responses={200: FileSerializer(many=True), 401: "Unauthorized"},
    )
    def get(self, request):
        try:
            logger.info("Starting MyFilesAPIView get method")
            files = File.objects.filter(user=request.user)
            serializer = FileSerializer(files, many=True)
            logger.info(f"Retrieved files for user: {request.user.email}")
            return Response({
                'status_code': status.HTTP_200_OK,
                'data': serializer.data,
            }, status=status.HTTP_200_OK)
        except AuthenticationFailed as e:
            logger.error(f"Authentication failed: {e}")
            return Response({
                'status_code': status.HTTP_401_UNAUTHORIZED,
                'error': 'Unauthorized',
            }, status=status.HTTP_401_UNAUTHORIZED)


class DeleteFileAPIView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Delete a file by ID",
        responses={204: "File deleted successfully", 404: "File not found", 401: "Unauthorized"},
    )
    def delete(self, request, file_id):
        try:
            logger.info(f"Starting DeleteFileAPIView delete method for file ID: {file_id}")
            file = get_object_or_404(File, id=file_id, user=request.user)
            try:
                minio_client.remove_object(settings.AWS_STORAGE_BUCKET_NAME, file.file.name)
                file.delete()
                logger.info(f"File deleted successfully: {file_id}")
                return Response({
                    'status_code': status.HTTP_204_NO_CONTENT,
                    'message': 'File deleted successfully',
                }, status=status.HTTP_204_NO_CONTENT)
            except Exception as e:
                logger.error(f"Error deleting file: {e}")
                return Response({
                    'status_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                    'error': f"Error deleting file: {e}",
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except AuthenticationFailed as e:
            logger.error(f"Authentication failed: {e}")
            return Response({
                'status_code': status.HTTP_401_UNAUTHORIZED,
                'error': 'Unauthorized',
            }, status=status.HTTP_401_UNAUTHORIZED)


class DownloadFileAPIView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Download a file",
        responses={
            200: "File downloaded successfully",
            404: "File not found",
            401: "Unauthorized",
        },
    )
    def get(self, request, file_id):
        try:
            logger.info(f"Starting DownloadFileAPIView get method for file ID: {file_id}")
            file = get_object_or_404(File, id=file_id, user=request.user)
            file_path = file.file.name
            response = minio_client.get_object(settings.AWS_STORAGE_BUCKET_NAME, file_path)

            def iter_file():
                for chunk in response.stream(32 * 1024):
                    yield chunk

            streaming_response = StreamingHttpResponse(iter_file(), content_type='application/octet-stream')
            streaming_response['Content-Disposition'] = f'attachment; filename="{file.name}"'
            logger.info(f"File downloaded successfully: {file_id}")
            return streaming_response
        except AuthenticationFailed as e:
            logger.error(f"Authentication failed: {e}")
            return Response({
                'status_code': status.HTTP_401_UNAUTHORIZED,
                'error': 'Unauthorized',
            }, status=status.HTTP_401_UNAUTHORIZED)


class DownloadTranscriptionAPIView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Download transcription of a file",
        responses={
            200: "Transcription downloaded successfully",
            404: "File not found",
            401: "Unauthorized",
        },
    )
    def get(self, request, file_id):
        try:
            logger.info(f"Starting DownloadTranscriptionAPIView get method for file ID: {file_id}")
            file = get_object_or_404(File, id=file_id, user=request.user)
            response = HttpResponse(file.transcription, content_type='text/plain')
            response['Content-Disposition'] = f'attachment; filename="{file.name}_transcription.srt"'
            logger.info(f"Transcription downloaded successfully: {file_id}")
            return response
        except AuthenticationFailed as e:
            logger.error(f"Authentication failed: {e}")
            return Response({
                'status_code': status.HTTP_401_UNAUTHORIZED,
                'error': 'Unauthorized',
            }, status=status.HTTP_401_UNAUTHORIZED)


class DownloadAnalysisAPIView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Download analysis result of a file",
        responses={
            200: "Analysis result downloaded successfully",
            404: "No analysis result available for this file",
            401: "Unauthorized",
        },
    )
    def get(self, request, file_id):
        try:
            logger.info(f"Starting DownloadAnalysisAPIView get method for file ID: {file_id}")
            file = get_object_or_404(File, id=file_id, user=request.user)
            if file.analysis_result:
                response = JsonResponse(file.analysis_result)
                response['Content-Disposition'] = f'attachment; filename="{file.name}_analysis.json"'
                logger.info(f"Analysis result downloaded successfully: {file_id}")
                return response
            else:
                logger.warning(f"No analysis result available for file ID: {file_id}")
                return Response({
                    'status_code': status.HTTP_404_NOT_FOUND,
                    'error': 'No analysis result available for this file',
                }, status=status.HTTP_404_NOT_FOUND)
        except AuthenticationFailed as e:
            logger.error(f"Authentication failed: {e}")
            return Response({
                'status_code': status.HTTP_401_UNAUTHORIZED,
                'error': 'Unauthorized',
            }, status=status.HTTP_401_UNAUTHORIZED)

