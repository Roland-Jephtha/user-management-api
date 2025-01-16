from rest_framework.test import APITestCase
from rest_framework import status
from django.contrib.auth.models import User




class UserManagementTests(APITestCase):
    def setUp(self):
        self.register_url = '/register/'
        self.login_url = '/login/'
        self.logout_url = '/logout/'
        self.profile_url = '/profile/'
        self.change_password_url = '/change-password/'

        self.user_data = {"email": "test@example.com", "password": "testpassword123"}

    def test_register_user(self):
        response = self.client.post(self.register_url, self.user_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_login_user(self):
        self.client.post(self.register_url, self.user_data)
        response = self.client.post(self.login_url, self.user_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_profile_view(self):
        user = User.objects.create_user(**self.user_data)
        self.client.force_authenticate(user)
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_change_password(self):
        user = User.objects.create_user(**self.user_data)
        self.client.force_authenticate(user)
        response = self.client.post(self.change_password_url, {
            "old_password": "testpassword123",
            "new_password": "newpassword123",
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)



    def test_logout_user(self):
        # Register and login user to get tokens
        self.client.post(self.register_url, self.user_data)
        login_response = self.client.post(self.login_url, self.user_data)
        refresh_token = login_response.data.get("refresh")

        # Logout the user
        response = self.client.post(self.logout_url, {"refresh": refresh_token})
        self.assertEqual(response.status_code, status.HTTP_205_RESET_CONTENT)

        # Try using the refresh token after logout
        invalid_response = self.client.post('/api/token/refresh/', {"refresh": refresh_token})
        self.assertEqual(invalid_response.status_code, status.HTTP_401_UNAUTHORIZED)
