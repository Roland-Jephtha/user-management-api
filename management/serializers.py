from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from .models import UserProfile
import requests
from django.core.files.base import ContentFile

User = get_user_model()

class RegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'password2')

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')
        user = User.objects.create_user(**validated_data)
        return user


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()







class UserProfileSerializer(serializers.ModelSerializer):
    profile_picture = serializers.CharField(required=False)

    class Meta:
        model = UserProfile
        fields = ('bio', 'profile_picture')

    def update(self, instance, validated_data):
        # Update bio
        instance.bio = validated_data.get('bio', instance.bio)

        # If there's a URL for the profile picture, fetch and save the image
        profile_picture_url = validated_data.get('profile_picture', None)
        if profile_picture_url:
            try:
                # Fetch the image from the URL
                response = requests.get(profile_picture_url)
                if response.status_code == 200:
                    # Save the image file
                    image_name = profile_picture_url.split("/")[-1]  # Get image filename from URL
                    image_content = ContentFile(response.content)  # Get image content
                    instance.profile_picture.save(image_name, image_content, save=True)  # Save image
            except Exception as e:
                raise serializers.ValidationError({"profile_picture": f"Error fetching the image: {str(e)}"})

        instance.save()
        return instance





class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, validators=[validate_password])
