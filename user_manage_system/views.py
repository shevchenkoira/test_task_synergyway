import logging

from rest_framework import status
from rest_framework.generics import RetrieveUpdateDestroyAPIView, ListCreateAPIView
from rest_framework.response import Response

from user_manage_system.models import CustomUser, CustomGroup
from user_manage_system.serializers import CustomUserDetailSerializer, GroupSerializer, CustomUserSerializer

logger = logging.getLogger(__name__)


class CustomUserListCreateView(ListCreateAPIView):
    """Generic API for users custom POST methods."""

    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer


class CustomUserDetailRUDView(RetrieveUpdateDestroyAPIView):
    """Generic API for users custom GET, PUT and DELETE methods.
    RUD - Retrieve, Update, Destroy.
    """

    queryset = CustomUser.objects.all()

    def get_serializer_class(self):
        logger.info(f"User {self.kwargs.get('pk')} is active.")

        return CustomUserDetailSerializer


class GroupListCreateView(ListCreateAPIView):
    """Generic API for group POST methods."""

    queryset = CustomGroup.objects.all()
    serializer_class = GroupSerializer


class GroupDetailRUDView(RetrieveUpdateDestroyAPIView):
    """Generic API for groups GET, PUT and DELETE methods.
    RUD - Retrieve, Update, Destroy.
    """

    queryset = CustomGroup.objects.all()

    def get_serializer_class(self):
        logger.info(f"Group {self.kwargs.get('pk')} is active.")

        return GroupSerializer

    def destroy(self, request, *args, **kwargs):
        try:
            CustomUser.objects.get(custom_group=kwargs.get("pk"))
        except Exception:
            return super().destroy(request, *args, **kwargs)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)
