
import logging
from django.contrib.auth.backends import BaseBackend
from .models import CustomUser

logger = logging.getLogger(__name__)

class EmailBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        logger.info(f"Authenticating user with email: {username}")  # Używamy username zamiast email
        try:
            user = CustomUser.objects.get(email=username)
            if user.check_password(password):
                return user
        except CustomUser.DoesNotExist:
            logger.warning(f"User with email {username} does not exist")
            return None

    def get_user(self, user_id):
        try:
            return CustomUser.objects.get(pk=user_id)
        except CustomUser.DoesNotExist:
            logger.warning(f"User with ID {user_id} does not exist")
            return None