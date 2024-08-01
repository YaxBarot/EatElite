import jwt
import datetime

from rest_framework import authentication
from rest_framework.exceptions import PermissionDenied, AuthenticationFailed
from django.conf import settings
from django.db.models import Q

from common.constants import TOKEN_EXPIRED
from common.models import CustomerAuthTokens
from ee_customers.models import Customers
from exceptions.generic import GenericException


def get_authentication_tokens(customer):
    access_token = jwt.encode({"user_id": customer.customer_id,
                               "email": customer.email,
                               "exp": datetime.datetime.now(tz=datetime.timezone.utc) + settings.ACCESS_TOKEN_LIFETIME,
                               "type": "access"},
                              settings.JWT_SECRET,
                              algorithm=settings.JWT_ALGORITHM)

    refresh_token = jwt.encode({"user_id": customer.customer_id,
                                "email": customer.email,
                                "exp": datetime.datetime.now(
                                    tz=datetime.timezone.utc) + settings.REFRESH_TOKEN_LIFETIME,
                                "type": "refresh"},
                               settings.JWT_SECRET,
                               algorithm=settings.JWT_ALGORITHM)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "access_token_expiry": settings.ACCESS_TOKEN_LIFETIME,
        "refresh_token_expiry": settings.REFRESH_TOKEN_LIFETIME
    }


def token_decode(token):
    try:
        claims = jwt.decode(token, settings.JWT_SECRET, algorithms=settings.JWT_ALGORITHM)

        if not CustomerAuthTokens.objects.filter(Q(access_token=token) | Q(refresh_token=token)).exists():
            raise AuthenticationFailed(detail=TOKEN_EXPIRED)

        if "user_id" not in claims:
            raise AuthenticationFailed(detail=TOKEN_EXPIRED)

        user = Customers.objects.get(id=claims["user_id"], email=claims["email"])

        return user, claims

    except Customers.DoesNotExist as e:
        raise AuthenticationFailed(detail=TOKEN_EXPIRED)

    except AuthenticationFailed as e:
        raise AuthenticationFailed(e.detail)

    except jwt.ExpiredSignatureError as e:
        raise AuthenticationFailed(detail=TOKEN_EXPIRED)

    except jwt.exceptions.InvalidSignatureError as e:
        raise AuthenticationFailed(detail=TOKEN_EXPIRED)

    except Exception as e:
        raise e


class CustomerJWTAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        try:
            if "authorization" not in request.headers:
                raise PermissionDenied()

            token = request.headers.get("authorization").split(" ")[1]

            return token_decode(token)

        except PermissionDenied as e:
            raise PermissionDenied()

        except Customers.DoesNotExist as e:
            raise AuthenticationFailed(detail=TOKEN_EXPIRED)

        except AuthenticationFailed as e:
            raise AuthenticationFailed(e.detail)

        except jwt.ExpiredSignatureError as e:
            raise AuthenticationFailed(detail=TOKEN_EXPIRED)

        except jwt.exceptions.DecodeError as e:
            raise AuthenticationFailed(detail=TOKEN_EXPIRED)

        except Exception as e:
            return GenericException()


