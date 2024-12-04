from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import UserViewSet, LoginAPIView, LogoutAPIView, RegisterAPIView, VerifyEmailAPIView, SetPasswordAPIView, \
    MainAPIView, ResendVerificationCodeAPIView, GoogleLoginAPIView, ForgotPasswordAPIView, \
    VerifyForgotPasswordCodeAPIView, ResetPasswordAPIView, YandexLoginAPIView

router = DefaultRouter()
router.register(r'users', UserViewSet)

app_name = 'accounts'

urlpatterns = [
    path('', include(router.urls)),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('register/', RegisterAPIView.as_view(), name='register'),
    path('verify_email/', VerifyEmailAPIView.as_view(), name='verify_email'),
    path('set_password/', SetPasswordAPIView.as_view(), name='set_password'),
    path('main/', MainAPIView.as_view(), name='main'),
    path('google-login/', GoogleLoginAPIView.as_view(), name='google-login'),
    path('yandex-login/', YandexLoginAPIView.as_view(), name='yandex-login'),
    path('resend-verification-code/', ResendVerificationCodeAPIView.as_view(), name='resend-verification-code'),
    path('forgot-password/', ForgotPasswordAPIView.as_view(), name='forgot-password'),
    path('verify-forgot-password-code/', VerifyForgotPasswordCodeAPIView.as_view(), name='verify-forgot-password-code'),
    path('reset-password/', ResetPasswordAPIView.as_view(), name='reset-password'),
]