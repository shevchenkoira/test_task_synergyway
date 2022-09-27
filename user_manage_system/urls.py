from django.urls import path

from user_manage_system.views import CustomUserDetailRUDView, CustomUserListCreateView, GroupListCreateView, \
    GroupDetailRUDView, FilteringView

urlpatterns = [
    path(
        "users/",
        CustomUserListCreateView.as_view(),
        name="user-list-create",
    ),
    path(
        "user/<int:pk>/",
        CustomUserDetailRUDView.as_view(),
        name="customuser-detail",
    ),
    path(
        "groups/",
        GroupListCreateView.as_view(),
        name="group-list-create",
    ),
    path(
        "group/<int:pk>/",
        GroupDetailRUDView.as_view(),
        name="group-detail",
    ),
    path(
        "filter/",
        FilteringView.as_view(),
        name="filter",
    ),
]
