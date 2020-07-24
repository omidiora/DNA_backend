
from django.contrib import admin
from django.urls import  path
from django.conf.urls import  include
from rest_framework.authtoken.views import obtain_auth_token
from api.views import CustomPasswordTokenVerificationView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/<version>/', include('api.urls')),
    path('api/<version>/login/', obtain_auth_token),  # Authenticate the login credentials and return the AuthToken
    path('api/<version>/reset-password/', include('django_rest_passwordreset.urls', namespace='password_reset')),
    path('api/<version>/reset-password/verify-token/', CustomPasswordTokenVerificationView, name='password_reset_verify_token'),
    
]
