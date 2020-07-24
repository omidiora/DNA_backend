from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework import viewsets, status
from django.contrib.auth.models import User
from rest_framework.decorators import action
from rest_framework.authentication import TokenAuthentication
from .models import Profile
from .serializers import   UserRegistrationSerializers, ProfileSerializer, EditProfileSerilizer, CustomTokenSerializer
from rest_framework.permissions import AllowAny, IsAuthenticated
from django_rest_passwordreset.models import ResetPasswordToken
from django_rest_passwordreset.views import get_password_reset_token_expiry_time
from django.core.mail import EmailMultiAlternatives
from django.dispatch import receiver
from django.template.loader import render_to_string
from rest_framework import parsers, renderers, status
from django.urls import reverse
from django.core.mail import send_mail
from django_rest_passwordreset.signals import reset_password_token_created

# from rest_framework.parsers import FileUploadParser

#login was
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class =  UserRegistrationSerializers
    authentication_classes = (TokenAuthentication,)
    permission_classes = (AllowAny,)
    versions =['v1']
    # update - default method should be restricted
    # pylint: disable=R0201
    def update(self, request, *args, **kwargs ):
        response = {'message': 'You cant Update your Profile like that'}
        return Response(response, status=status.HTTP_400_BAD_REQUEST)

    # destroy - IsAuthenticated an isSelf
    # pylint: disable=R0201
    def destroy(self, request,  *args, **kwargs):
        response = {'message': 'You cant delete Profile like this'}
        return Response(response, status=status.HTTP_400_BAD_REQUEST)

    # retrieve - default method for all should be restricted,
    # pylint: disable=R0201
    def list(self, request, *args, **kwargs):
        response = {'message': 'You cant  list or retrieve users Profile like this'}
        return Response(response, status=status.HTTP_400_BAD_REQUEST)
    # pylint: disable=R0201
    def retrieve(self, request, pk=None, *args, **kwargs):
        response = {'message': 'You cant  list or retrieve users Profile like this'}
        return Response(response, status=status.HTTP_400_BAD_REQUEST)



class ProfileViewSet(viewsets.ModelViewSet):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    authentication_classes = (TokenAuthentication,)  #this option is used to authenticate a user, thus django can identify the token and its owner
    permission_classes = (IsAuthenticated,)
    versions = ['v1']
    # only set permissions for actions as update
    # remember to customise Create, delete, retrieve

    # pylint: disable=R0201
    def update(self, request, *args, **kwargs):
        response = {'message': 'You cant edit your Profile like that'}
        return Response(response, status=status.HTTP_400_BAD_REQUEST)

    # pylint: disable=R0201
    def create(self, request, *args, **kwargs):
        response = {'message': 'You cant create Profile like that'}
        return Response(response, status=status.HTTP_400_BAD_REQUEST)

    # pylint: disable=R0201
    def destroy(self, request,  *args, **kwargs):
        response = {'message': 'You cant delete Profile like this'}
        return Response(response, status=status.HTTP_400_BAD_REQUEST)

    # pylint: disable=R0201
    def list(self, request, version="v1", *args, **kwargs):
            # check if the version argument exists in the versions list
         if version in self.versions:

                if request.user:
                    try:
                        user = request.user
                        profile = Profile.objects.get(user=user.id)
                        serializer = ProfileSerializer(profile, many=False)
                        response = {'message': 'User profile ', 'result': serializer.data}
                        return Response(response, status=status.HTTP_200_OK)
                    except IndexError:
                        response = {'message': 'User not Authenticated! '}
                        return Response(response, status=status.HTTP_400_BAD_REQUEST)

         else:
            response = {'message': 'API version not identified!'}
            return Response(response, status=status.HTTP_400_BAD_REQUEST)


    # pylint: disable=R0201
    def retrieve(self, request, pk=None,  *args, **kwargs):
        response = {'message': 'You cant retrieve users Profile like this'}
        return Response(response, status=status.HTTP_400_BAD_REQUEST)


    # write a custom method that uses the authToken for access privileges
    # pylint: disable=R0201
    @action(detail=True, methods=['PUT'])
    def update_profile(self, request, version="v1", pk=None,):
        # check if the version argument exists in the versions list
        if version in self.versions:
            if request.data :
                fetched_data =  request.data
                user = request.user
                try :
                     profile = Profile.objects.filter(user=user.id, id=pk )
                     profile.update(facebook_user=fetched_data['facebook_user'],
                                    phone=fetched_data['phone'],
                                    profile=request.FILES.get('profile'))
                     get_profile = Profile.objects.get(user=user.id, id=pk)
                     serializer = EditProfileSerilizer(get_profile, many=False)
                     response = {'message': 'User profile  Updated', 'result': serializer.data}
                     return Response(response, status=status.HTTP_200_OK)

                except IndexError :
                    response = {'message': 'user profile does not exit'}
                    return Response(response, status=status.HTTP_404_OK)
        else:
            response = {'message': 'API version not identified!'}
            return Response(response, status=status.HTTP_400_BAD_REQUEST)

class CustomPasswordResetView:
    @receiver(reset_password_token_created)
    def password_reset_token_created(sender, reset_password_token, *args, **kwargs):
        """
          Handles password reset tokens
          When a token is created, an e-mail needs to be sent to the user
        """
        site_url = "localhost:8000"
        site_shortcut_name ="DNA"
        site_full_name = "Debt Notification system"
        # send an e-mail to the user
        context = {
            'current_user': reset_password_token.user,
            'username': reset_password_token.user.username,
            'email': reset_password_token.user.email,
            'reset_password_url': "{}/password-reset/{}".format(site_url, reset_password_token.key),
            'site_name': site_shortcut_name,
            'site_domain': site_url
        }

        # render email text
        email_html_message = render_to_string('email/user_reset_password.html', context)
        email_plaintext_message = render_to_string('email/user_reset_password.txt', context)

        # msg = EmailMultiAlternatives(
        #     # title:
        #     "Password Reset for {}".format(site_full_name),
        #     # message:
        #     email_plaintext_message,
        #     # from:
        #     "noreply@{}".format(site_url),
        #     # to:
        #     [reset_password_token.user.email]
        # )
        # msg.attach_alternative(email_html_message, "text/html")
        # msg.send()
        send_mail(
        'password recovery',
        "{}/password-reset/{}".format(site_url, reset_password_token.key),
        'recovery@mail.com',
        [reset_password_token.user.email],
        fail_silently=False,
        )


class CustomPasswordTokenVerificationView(viewsets.ModelViewSet):
    """
      An Api View which provides a method to verifiy that a given pw-reset token is valid before actually confirming the
      reset.
    """
    throttle_classes = ()
    permission_classes = ()
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, parsers.JSONParser,)
    renderer_classes = (renderers.JSONRenderer,)
    serializer_class = CustomTokenSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data['token']

        # get token validation time
        password_reset_token_validation_time = get_password_reset_token_expiry_time()

        # find token
        reset_password_token = ResetPasswordToken.objects.filter(key=token).first()

        if reset_password_token is None:
            return Response({'status': 'invalid'}, status=status.HTTP_404_NOT_FOUND)

        # check expiry date
        expiry_date = reset_password_token.created_at + timedelta(hours=password_reset_token_validation_time)

        if timezone.now() > expiry_date:
            # delete expired token
            reset_password_token.delete()
            return Response({'status': 'expired'}, status=status.HTTP_404_NOT_FOUND)

        # check if user has password to change
        if not reset_password_token.user.has_usable_password():
            return Response({'status': 'irrelevant'})

        return Response({'status': 'OK'})