import logging

from django.contrib.auth.hashers import make_password
from django.http import QueryDict
from rest_framework import status, serializers
from rest_framework.generics import RetrieveUpdateDestroyAPIView, ListCreateAPIView, GenericAPIView, RetrieveAPIView, \
    CreateAPIView
from rest_framework.response import Response

from user_manage_system.models import CustomUser, CustomGroup
from user_manage_system.serializers import CustomUserDetailSerializer, CustomGroupSerializer, CustomUserSerializer

logger = logging.getLogger(__name__)


class CustomUserListCreateView(ListCreateAPIView):
    """Generic API for users custom POST methods."""

    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer

    def post(self, request, *args, **kwargs):
        print(request.data)
        return super().post(request, *args, **kwargs)


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
    serializer_class = CustomGroupSerializer


class GroupDetailRUDView(RetrieveUpdateDestroyAPIView):
    """Generic API for groups GET, PUT and DELETE methods.
    RUD - Retrieve, Update, Destroy.
    """

    queryset = CustomGroup.objects.all()

    def get_serializer_class(self):
        logger.info(f"Group {self.kwargs.get('pk')} is active.")

        return CustomGroupSerializer

    def destroy(self, request, *args, **kwargs):
        try:
            CustomUser.objects.get(custom_group=kwargs.get("pk"))
        except Exception:
            return super().destroy(request, *args, **kwargs)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class FilteringView(GenericAPIView):
    """Generic API for filtering query"""

    function_dict = {
        "like": "{} LIKE '{}'",
        "exact": "{} = {}",
    }
    model_dict = {
        "CustomUser": "user_manage_system_customuser",
        "CustomGroup": "user_manage_system_customgroup",
    }

    def post(self, request, *args, **kwargs):
        try:
            self.filter_data(request.data)
        except Exception:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        serializer = self.serializer_class(self.queryset, context={'request': request}, many=True)
        return Response(status=status.HTTP_200_OK, data=serializer.data)

    def filter_data(self, data):
        if not isinstance(data.get("table"), str):
            raise TypeError
        table_name = data.get("table")
        filters = data.get("filter")

        query = [f"SELECT * FROM {self.model_dict[table_name]} WHERE"]
        for table_filter in filters:
            try:
                if isinstance(table_filter["filter_input"], str):
                    table_filter["filter_input"] = "'" + table_filter["filter_input"] + "'"
                query.append(self.function_dict[table_filter["filter_function"]].format(table_filter["field"],
                                                                                        table_filter["filter_input"]))
            except KeyError:
                raise KeyError
            query.append("AND")
        query[-1] = ";"

        self.queryset = eval(f"{table_name}.objects.raw(' '.join(query))")
        self.serializer_class = eval(f"{table_name}Serializer")
