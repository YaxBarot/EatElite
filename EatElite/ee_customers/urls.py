from django.urls import path

from .views import Registration, Login, OTPVerification, ForgotPassword


urlpatterns = [
    path("register/", Registration.as_view()),
    path("login/", Login.as_view()),
    path("otpverification/", OTPVerification.as_view()),
    path("forgotpassword/", ForgotPassword.as_view()),

]
