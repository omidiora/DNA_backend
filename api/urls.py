from django.contrib import admin
from django.urls import path
from rest_framework import routers
from django.conf.urls import include
from .views import UserViewSet, ProfileViewSet

router = routers.DefaultRouter()
router.register('user', UserViewSet)
router.register('profile', ProfileViewSet)

urlpatterns = [
    path('v1/', include(router.urls)),
]
