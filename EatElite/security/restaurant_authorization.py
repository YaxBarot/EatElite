import jwt
import datetime

from django.conf import settings
from django.db.models import Q
from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied

from common.serializers import RestaurantAuthTokenSerializer

from common.models import RestaurantAuthTokens

from common.constants import TOKEN_EXPIRED

from restaurant.models import RestaurantProfile


def save_restaurant_auth_tokens(authentication_tokens):
    restaurant_auth_token_serializer = RestaurantAuthTokenSerializer(data=authentication_tokens)
    if restaurant_auth_token_serializer.is_valid():
        restaurant_auth_token_serializer.save()


def get_restaurant_authentication_tokens(restaurant):
    access_token = jwt.encode({"restaurant_id": restaurant.restaurant_id,
                               "email": restaurant.email,
                               "exp": datetime.datetime.now(tz=datetime.timezone.utc) + settings.ACCESS_TOKEN_LIFETIME,
                               "type": "access"},
                              settings.JWT_SECRET,
                              algorithm=settings.JWT_ALGORITHM)

    refresh_token = jwt.encode({"restaurant_id": restaurant.restaurant_id,
                                "email": restaurant.email,
                                "exp": datetime.datetime.now(tz=datetime.timezone.utc) + settings.REFRESH_TOKEN_LIFETIME,
                                "type": "refresh"},
                               settings.JWT_SECRET,
                               algorithm=settings.JWT_ALGORITHM)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "access_token_expiry": settings.ACCESS_TOKEN_LIFETIME,
        "refresh_token_expiry": settings.REFRESH_TOKEN_LIFETIME
    }


def restaurant_token_decode(token):
    try:
        claims = jwt.decode(token, settings.JWT_SECRET, algorithms=settings.JWT_ALGORITHM)

        if not RestaurantAuthTokens.objects.filter(Q(access_token=token) | Q(refresh_token=token)).exists():
            raise AuthenticationFailed(detail=TOKEN_EXPIRED)

        if "restaurant_id" not in claims:
            raise AuthenticationFailed(detail=TOKEN_EXPIRED)

        restaurant = RestaurantProfile.objects.get(restaurant_id=claims["restaurant_id"],
                                         email=claims["email"],
                                         is_deleted=False)

        return restaurant, claims

    except RestaurantProfile.DoesNotExist as e:
        raise AuthenticationFailed(detail=TOKEN_EXPIRED)

    except AuthenticationFailed as e:
        raise AuthenticationFailed(detail=TOKEN_EXPIRED)

    except jwt.ExpiredSignatureError as e:
        raise AuthenticationFailed(detail=TOKEN_EXPIRED)

    except jwt.exceptions.InvalidSignatureError as e:
        raise AuthenticationFailed(detail=TOKEN_EXPIRED)

    except Exception as e:
        raise e


class RestaurantJWTAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        try:
            if "authorization" not in request.headers:
                raise PermissionDenied()

            token = request.headers.get("authorization").split(" ")[1]

            return restaurant_token_decode(token)

        except PermissionDenied as e:
            raise PermissionDenied()

        except AuthenticationFailed as e:
            raise AuthenticationFailed(e.detail)

        except jwt.ExpiredSignatureError as e:
            raise AuthenticationFailed(detail=TOKEN_EXPIRED)

        except jwt.exceptions.DecodeError as e:
            raise AuthenticationFailed(detail=TOKEN_EXPIRED)
