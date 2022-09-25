from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.hashers import make_password
import logging

from rest_framework.exceptions import ValidationError

from user_manage_system.models import CustomUser, Group

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
        view_name="user_manage_system:user-detail", lookup_field="pk",
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
    group = serializers.HyperlinkedRelatedField(
        view_name="user_manage_system:user-groups", lookup_field="pk",
    )

    class Meta:
        """Class with a model and model fields for serialization."""

        model = CustomUser
        fields = ("url", "id", "email", "username", "group", "email",
                  "created_at", "password", "confirm_password")

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

    group = serializers.HyperlinkedRelatedField(
        view_name="user_manage_system:user-groups", lookup_field="pk",
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
        fields = ("url", "id", "email", "username", "group", "email",
                  "created_at", "password", "confirm_password")

    def update(self, instance: object, validated_data: dict) -> object:
        confirm_password = validated_data.get("confirm_password", None)
        if confirm_password:
            validated_data["password"] = make_password(confirm_password)
        else:
            validated_data["password"] = instance.password

        logger.info(f"Data for user {instance} was updated")

        return super().update(instance, validated_data)


class GroupSerializer(serializers.HyperlinkedModelSerializer):
    """Serializer for getting all groups and creating a new one."""

    url = serializers.HyperlinkedIdentityField(
        view_name="api:order-detail", lookup_field="pk",
    )
    user = serializers.HyperlinkedRelatedField(
        view_name="user_manage_system:user-detail", lookup_field="pk",
    )

    class Meta:
        """Class with a model and model fields for serialization."""

        model = Group
        fields = "__all__"

    def validate(self, attrs):
        users = attrs.get("user")
        name = attrs.get("name")

        errors = {}

        if not users.groups.filter(name=name):
            logger.info(f"Group {name} does not have {users.username} user")

            errors.update(
                {"group": {"message": f"Group {name} does not have {users.username} user",
                             "help_text": f"Group {name} has such users {list(users)}"}},
            )

        if errors:
            raise ValidationError(errors)
        return super().validate(attrs)
