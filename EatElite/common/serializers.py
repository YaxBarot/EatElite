from rest_framework import serializers

from .models import CustomerAuthTokens


class CustomerAuthTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomerAuthTokens
        fields = "__all__"
