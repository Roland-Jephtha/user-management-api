from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from .models import UserProfile
from .serializers import (
    LoginSerializer,
    RegistrationSerializer,
    UserProfileSerializer,
    ChangePasswordSerializer,
)
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi



from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from .serializers import RegistrationSerializer
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.contrib.auth import get_user_model

from django.utils.crypto import get_random_string
from datetime import datetime, timedelta
from django.conf import settings
from django.core.mail import EmailMultiAlternatives










class RegisterView(APIView):
    """
    API for user registration and email verification via OTP.
    """
    
    @swagger_auto_schema(
        operation_description="Register a new user and send an email with OTP for verification.",
        request_body=RegistrationSerializer,
        responses={
            201: 'User registered successfully. Please check your email to verify your account.',
            400: 'Bad request - validation errors.',
        }
    )
    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.is_active = False  # Make user inactive until email is verified
            user.save()

            # Generate OTP and save it for validation
            otp = get_random_string(6, allowed_chars='0123456789')  # 6-digit OTP
            expiration_time = datetime.now() + timedelta(minutes=10)  # OTP valid for 10 minutes

            user.profile.verification_otp = otp
            user.profile.otp_expiration = expiration_time
            user.profile.save()

            self.send_otp_email(user, otp)
            return Response({"message": "Registration successful. Please check your email for the OTP to verify your account."},
                             status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

def send_otp_email(self, user, otp):
    subject = "Activate Your Account with OTP"
    from_email = settings.DEFAULT_FROM_EMAIL
    to_email = [user.email]

    # Render HTML message
    html_message = render_to_string("activation_email.html", {
        'user': user,
        'otp': otp,
    })

    # Create email with HTML content
    email = EmailMultiAlternatives(subject=subject, from_email=from_email, to=to_email)
    email.attach_alternative(html_message, "text/html")
    email.send()







from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.utils.timezone import now
from django.contrib.auth import get_user_model

User = get_user_model()

class EmailVerificationView(APIView):
    """
    API to verify the email address using the OTP sent to the user's email.
    """

    @swagger_auto_schema(
        operation_description="Verify the email address using the OTP sent to the user's email.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email address of the user'),
                'otp': openapi.Schema(type=openapi.TYPE_STRING, description='OTP sent to the user email for verification'),
            },
            required=['email', 'otp'],
        ),
        responses={
            200: openapi.Response(description='Email verified successfully!'),
            400: openapi.Response(description='Invalid email, OTP, or OTP expired.'),
            404: openapi.Response(description='User with the provided email not found.'),
        }
    )
    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')

        # Validate input
        if not email or not otp:
            return Response({"message": "Both email and OTP are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Find the user by email
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"message": f"User with email '{email}' not found."}, status=status.HTTP_404_NOT_FOUND)

        # Check if OTP matches and hasn't expired
        if user.profile.verification_otp == otp:
            if user.profile.otp_expiration and user.profile.otp_expiration >= now():
                user.is_active = True  # Activate the user
                user.save()

                # Clear OTP after successful verification
                user.profile.verification_otp = None
                user.profile.otp_expiration = None
                user.profile.save()

                return Response({"message": "Email verified successfully!"}, status=status.HTTP_200_OK)
            else:
                return Response({"message": "OTP has expired."}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"message": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)


# User Login View
class LoginView(APIView):
    """
    API for user login.
    """

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["email", "password"],
            properties={
                "email": openapi.Schema(type=openapi.TYPE_STRING, description="Registered email address"),
                "password": openapi.Schema(type=openapi.TYPE_STRING, description="User's password"),
            },
            example={
                "email": "user@gmail.com",
                "password": "securepassword123",
            },
        ),
        responses={
            200: openapi.Response("Login successful, returns access and refresh tokens."),
            401: openapi.Response("Invalid credentials"),
        },
        operation_description="Authenticate a user by email and password to receive JWT tokens.",
    )
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = authenticate(username=email, password=password)

        if user:
            refresh = RefreshToken.for_user(user)
            return Response({
                "access": str(refresh.access_token),
                "refresh": str(refresh),
            }, status=status.HTTP_200_OK)
        return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

class UserProfileView(APIView):
    def put(self, request, *args, **kwargs):
        user_profile = request.user.profile
        serializer = UserProfileSerializer(user_profile, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request, *args, **kwargs):
        user_profile = request.user.profile
        serializer = UserProfileSerializer(user_profile, data=request.data, many = False)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


# Change Password View
class ChangePasswordView(APIView):
    """
    API to change the authenticated user's password.
    """
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["old_password", "new_password"],
            properties={
                "old_password": openapi.Schema(type=openapi.TYPE_STRING, description="Current password"),
                "new_password": openapi.Schema(type=openapi.TYPE_STRING, description="New password"),
            },
            example={
                "old_password": "currentpassword123",
                "new_password": "newsecurepassword456",
            },
        ),
        responses={
            200: openapi.Response("Password updated successfully"),
            400: openapi.Response("Bad Request"),
        },
        operation_description="Change the user's password by providing the current and new passwords.",
    )
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            if not request.user.check_password(serializer.validated_data['old_password']):
                return Response({"error": "Incorrect old password"}, status=status.HTTP_400_BAD_REQUEST)
            request.user.set_password(serializer.validated_data['new_password'])
            request.user.save()
            return Response({"message": "Password updated successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Logout View
class LogoutView(APIView):
    """
    API to log out the user by blacklisting the refresh token.
    """
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["refresh"],
            properties={
                "refresh": openapi.Schema(type=openapi.TYPE_STRING, description="JWT refresh token"),
            },
            example={
                "refresh": "your_refresh_token_here",
            },
        ),
        responses={
            205: openapi.Response("Successfully logged out"),
            400: openapi.Response("Invalid token"),
        },
        operation_description="Log out the user by blacklisting the provided refresh token.",
    )
    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Successfully logged out"}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)
