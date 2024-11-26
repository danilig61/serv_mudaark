from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import UserViewSet, LoginAPIView, LogoutAPIView, RegisterAPIView, VerifyEmailAPIView, SetPasswordAPIView, \
    MainAPIView, ResendVerificationCodeAPIView, GoogleLoginRedirectAPI, GoogleLoginAPI

router = DefaultRouter()
router.register(r'users', UserViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('register/', RegisterAPIView.as_view(), name='register'),
    path('verify_email/', VerifyEmailAPIView.as_view(), name='verify_email'),
    path('set_password/', SetPasswordAPIView.as_view(), name='set_password'),
    path('main/', MainAPIView.as_view(), name='main'),
    path('auth/', include('social_django.urls', namespace='social')),
    path('google-auth/', GoogleLoginRedirectAPI.as_view(), name='google-auth'),
    path('google-auth/callback/', GoogleLoginAPI.as_view(), name='google-auth-callback'),
    path('resend-verification-code/', ResendVerificationCodeAPIView.as_view(), name='resend-verification-code'),

]
