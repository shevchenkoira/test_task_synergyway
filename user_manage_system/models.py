from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.core.validators import validate_email
from django.db import models


class CustomGroup(models.Model):
    name = models.CharField(
        max_length=40,
        verbose_name="Name",
        unique=True,
    )
    description = models.CharField(
        verbose_name="Description",
        max_length=255,
    )

    def __str__(self):
        """str: Returns name of Group."""
        return self.name

    class Meta:
        """This meta class stores verbose names and ordering data."""

        ordering = ["name"]
        verbose_name = "CustomGroup"
        verbose_name_plural = "CustomGroups"


class CustomUser(PermissionsMixin, AbstractBaseUser):
    username = models.CharField(
        max_length=30,
        unique=True,
    )
    email = models.EmailField(
        max_length=70,
        unique=True,
        validators=(validate_email,),
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        editable=False,
    )
    custom_group = models.ManyToManyField(
        CustomGroup, related_name="users", blank=True, null=True, default=[]
    )

    is_admin = models.BooleanField(default=False)

    USERNAME_FIELD = "username"

    REQUIRED_FIELDS = ("password", "confirm_password", "email")

    class Meta:
        """This meta class stores verbose names ordering data."""

        ordering = ["id"]
        verbose_name = "User"
        verbose_name_plural = "Users"

    @property
    def is_staff(self):
        """Determines whether user is admin."""
        return self.is_admin

    def __str__(self):
        """str: Returns username of the user."""
        return self.username
