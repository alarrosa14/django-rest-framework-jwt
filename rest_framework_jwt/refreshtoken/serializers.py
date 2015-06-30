from datetime import datetime

from django.utils.translation import ugettext as _
from rest_framework import exceptions
from rest_framework import serializers
from rest_framework_jwt.compat import CurrentUserDefault, Serializer

from rest_framework_jwt.settings import api_settings

from .models import RefreshToken

jwt_refresh_expiration_delta = api_settings.JWT_REFRESH_EXPIRATION_DELTA

class RefreshTokenSerializer(serializers.ModelSerializer):
    """
    Serializer for refresh tokens (Not RefreshJWTToken)
    """

    user = serializers.PrimaryKeyRelatedField(
        required=False,
        read_only=True,
        default=CurrentUserDefault())

    class Meta:
        model = RefreshToken
        fields = ('key', 'user', 'created', 'app')
        read_only_fields = ('key', 'created')

    def validate(self, attrs):
        """
        only for DRF < 3.0 support.
        Otherwise CurrentUserDefault() is doing the job of obtaining user
        from current request.
        """
        if 'user' not in attrs:
            attrs['user'] = self.context['request'].user
        return attrs


class DelegateJSONWebTokenSerializer(Serializer):
    refresh_token = serializers.CharField()

    def validate(self, attrs):
        refresh_token = attrs['refresh_token']
        try:
            token = RefreshToken.objects.select_related('user').get(
                key=refresh_token)
            token_expiration_time = token.created.replace(tzinfo=None) + \
                jwt_refresh_expiration_delta
            if datetime.now() > token_expiration_time:
                raise exceptions.AuthenticationFailed(_('Expired token.'))
        except RefreshToken.DoesNotExist:
            raise exceptions.AuthenticationFailed(_('Invalid token.'))
        attrs['user'] = token.user
        return attrs
