from django.urls import path
from .views import (
    UploadFileAPIView, MyFilesAPIView, DeleteFileAPIView, DownloadFileAPIView, DownloadTranscriptionAPIView,
    DownloadAnalysisAPIView, UserInfoAPIView
)

app_name = 'files'

urlpatterns = [
    path('upload/', UploadFileAPIView.as_view(), name='upload_file'),
    path('my_files/', MyFilesAPIView.as_view(), name='my_files'),
    path('delete/<int:file_id>/', DeleteFileAPIView.as_view(), name='delete_file'),
    path('download/<int:file_id>/', DownloadFileAPIView.as_view(), name='download_file'),
    path('download_transcription/<int:file_id>/', DownloadTranscriptionAPIView.as_view(), name='download_transcription'),
    path('download_analysis/<int:file_id>/', DownloadAnalysisAPIView.as_view(), name='download_analysis'),
    path('user_info/', UserInfoAPIView.as_view(), name='user_info'),
]