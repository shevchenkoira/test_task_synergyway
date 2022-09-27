from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.hashers import make_password
import logging

from user_manage_system.models import CustomUser, CustomGroup

logger = logging.getLogger(__name__)


class PasswordsValidation(serializers.Serializer):
    """Validator for passwords."""

    def validate(self, data: dict) -> dict:
        password = data.get("password")
        confirm_password = data.get("confirm_password")
        if password and confirm_password:
            if password != confirm_password:
                logger.info("Password: Password confirmation does not match")

                raise serializers.ValidationError(
                    {"password": "Password confirmation does not match."},
                )
        elif any([password, confirm_password]):

            logger.info("Password: One of the password fields is empty")

            raise serializers.ValidationError(
                {"confirm_password": "Didn`t enter the password confirmation."},
            )

        logger.info("Password and Confirm password is checked")

        return super().validate(data)


class CustomUserSerializer(PasswordsValidation,
                           serializers.HyperlinkedModelSerializer):
    """Serializer for getting all users and creating a new user."""

    url = serializers.HyperlinkedIdentityField(
        view_name="customuser-detail", lookup_field="pk",
    )
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={"input_type": "password", "placeholder": "Password"},
        validators=[validate_password],
    )
    confirm_password = serializers.CharField(
        write_only=True,
        required=True,
        style={"input_type": "password",
               "placeholder": "Confirmation Password",
               },
    )
    custom_group = serializers.HyperlinkedRelatedField(
        view_name="group-detail", queryset=CustomGroup.objects.all(), many=True,
    )

    class Meta:
        """Class with a model and model fields for serialization."""

        model = CustomUser
        fields = ("url", "id", "email", "username", "custom_group", "email",
                  "created_at", "password", "confirm_password", "is_admin")

    def create(self, validated_data: dict) -> object:
        confirm_password = validated_data.pop("confirm_password")
        validated_data["password"] = make_password(confirm_password)

        logger.info(f"User {validated_data['username']} with"
                    f" {validated_data['email']} was created.")

        return super().create(validated_data)

    def to_representation(self, instance):
        data = super().to_representation(instance)
        return data


class CustomUserDetailSerializer(PasswordsValidation, serializers.ModelSerializer):
    """Serializer to receive and update a specific user."""

    custom_group = serializers.HyperlinkedRelatedField(
        view_name="group-detail", queryset=CustomGroup.objects.all(), many=True,
    )
    password = serializers.CharField(
        write_only=True,
        allow_blank=True,
        validators=[validate_password],
        style={"input_type": "password", "placeholder": "New Password"},
    )
    confirm_password = serializers.CharField(
        write_only=True,
        allow_blank=True,
        help_text="Leave empty if no change needed",
        style={
            "input_type": "password",
            "placeholder": "Confirmation Password",
        },
    )

    class Meta:
        """Class with a model and model fields for serialization."""

        model = CustomUser
        fields = ("url", "id", "email", "username", "custom_group",
                  "created_at", "password", "confirm_password", "is_admin")

    def update(self, instance: object, validated_data: dict) -> object:
        confirm_password = validated_data.get("confirm_password", None)

        if confirm_password:
            validated_data["password"] = make_password(confirm_password)
        else:
            validated_data["password"] = instance.password

        logger.info(f"Data for user {instance} was updated")

        return super().update(instance, validated_data)


class CustomGroupSerializer(serializers.HyperlinkedModelSerializer):
    """Serializer for getting all groups and creating a new one."""

    url = serializers.HyperlinkedIdentityField(
        view_name="group-detail", lookup_field="pk",
    )

    users = CustomUserSerializer(read_only=True, many=True)

    class Meta:
        """Class with a model and model fields for serialization."""

        model = CustomGroup
        fields = ("id", "name", "description", "users", "url")
