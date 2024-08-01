import re
import random
import traceback

from django.utils import timezone
from rest_framework.views import APIView

from .serializers import RegistrationSerializer, OTPVerificationSerializer, ResetPasswordSerializer
from .models import Customers, CustomerOTP

from common.helpers import save_customer_auth_tokens, send_mail
from common.constants import PASSWORD_LENGTH_SHOULD_BE_BETWEEN_8_TO_20, PASSWORD_MUST_HAVE_ONE_NUMBER, \
    PASSWORD_MUST_HAVE_ONE_SMALLERCASE_LETTER, PASSWORD_MUST_HAVE_ONE_UPPERCASE_LETTER, \
    PASSWORD_MUST_HAVE_ONE_SPECIAL_CHARACTER, EMAIL_ALREADY_EXISTS, MOBILE_NO_ALREADY_EXISTS, \
    USER_REGISTERED_SUCCESSFULLY, BAD_REQUEST, USER_LOGGED_IN_SUCCESSFULLY, WRONG_EMAIL, INCORRECT_PASSWORD, \
    OTP_SENT_SUCCESSFULLY_TO_YOUR_EMAIL_ID, NEW_PASSWORD_DOESNT_MATCH, OTP_EXPIRED, OTP_DOESNT_MATCH, \
    YOUR_PASSWORD_UPDATED_SUCCESSFULLY
from exceptions.generic import CustomBadRequest, BadRequest, GenericException
from exceptions.generic_response import GenericSuccessResponse
from security.customer_authorization import get_authentication_tokens, CustomerJWTAuthentication


class Registration(APIView):
    @staticmethod
    def post(request):
        try:
            registration_serializer = RegistrationSerializer(data=request.data)

            if "password" in request.data:
                password = request.data["password"]
                special_characters = r"[\$#@!\*]"

                # validation
                if len(password) < 8 or len(password) > 20:
                    return CustomBadRequest(message=PASSWORD_LENGTH_SHOULD_BE_BETWEEN_8_TO_20)
                elif re.search('[0-9]', password) is None:
                    return CustomBadRequest(message=PASSWORD_MUST_HAVE_ONE_NUMBER)
                elif re.search('[a-z]', password) is None:
                    return CustomBadRequest(message=PASSWORD_MUST_HAVE_ONE_SMALLERCASE_LETTER)
                elif re.search('[A-Z]', password) is None:
                    return CustomBadRequest(message=PASSWORD_MUST_HAVE_ONE_UPPERCASE_LETTER)
                elif re.search(special_characters, password) is None:
                    return CustomBadRequest(message=PASSWORD_MUST_HAVE_ONE_SPECIAL_CHARACTER)

            if "email" in request.data and Customers.objects.filter(email=request.data["email"],
                                                                    is_deleted=False).exists():
                return CustomBadRequest(message=EMAIL_ALREADY_EXISTS)

            if "mobile_no" in request.data and Customers.objects.filter(mobile_no=request.data["mobile_no"],
                                                                        is_deleted=False).exists():
                return CustomBadRequest(message=MOBILE_NO_ALREADY_EXISTS)

            if registration_serializer.is_valid(raise_exception=True):

                customer = registration_serializer.save()
                authentication_tokens = get_authentication_tokens(customer)
                save_customer_auth_tokens(authentication_tokens)

                return GenericSuccessResponse(authentication_tokens, message=USER_REGISTERED_SUCCESSFULLY)
            else:
                return CustomBadRequest(message=BAD_REQUEST)
        except BadRequest as e:
            raise BadRequest(e.detail)

        except Exception as e:
            return GenericException()


class Login(APIView):
    @staticmethod
    def post(request):
        try:
            email = request.data.get("email")
            password = request.data.get("password")

            if not email or not password:
                return CustomBadRequest(message=BAD_REQUEST)

            customer = Customers.objects.get(email=email, is_deleted=False)

            if not (password == customer.password):
                return CustomBadRequest(message=INCORRECT_PASSWORD)

            authentication_tokens = get_authentication_tokens(customer)
            save_customer_auth_tokens(authentication_tokens)

            return GenericSuccessResponse(data=authentication_tokens, message=USER_LOGGED_IN_SUCCESSFULLY)

        except Customers.DoesNotExist:
            return CustomBadRequest(message=WRONG_EMAIL)

        except Exception as e:
            return GenericException()


class OTPVerification(APIView):
    def post(self, request):
        try:
            email = request.data.get("email")

            if not email:
                return CustomBadRequest(message=BAD_REQUEST)

            otp = str(random.randint(1000, 9999))
            customer = Customers.objects.get(email=email, is_deleted=False)

            otp_verification_data = {
                "otp": otp,
                "customer_id": customer.customer_id
            }
            otp_verification_serializer = OTPVerificationSerializer(data=otp_verification_data)

            if otp_verification_serializer.is_valid():
                otp_verification_serializer.save()
                send_mail([email], msg=otp)
                return GenericSuccessResponse(message=OTP_SENT_SUCCESSFULLY_TO_YOUR_EMAIL_ID)
            else:
                return CustomBadRequest(message=BAD_REQUEST)

        except Customers.DoesNotExist:
            return CustomBadRequest(message=WRONG_EMAIL)

        except Exception as e:
            traceback.print_exc(e)
            return GenericException()


class ForgotPassword(APIView):
    @staticmethod
    def patch(request):
        try:
            if "email" not in request.data or "new_password" not in request.data or "confirm_password" not in request.data or "otp" not in request.data:
                raise CustomBadRequest(message=BAD_REQUEST)

            new_password = request.data["new_password"]
            confirm_password = request.data["confirm_password"]
            email = request.data["email"]
            otp = request.data["otp"]

            del request.data["new_password"]
            del request.data["confirm_password"]
            del request.data["email"]
            del request.data["otp"]

            reset_password_serializer = ResetPasswordSerializer(data=request.data)
            customer = Customers.objects.get(email=email, is_deleted=False)
            customer_otp = CustomerOTP.objects.filter(customer_id=customer.customer_id).last()

            if new_password == confirm_password:
                if (timezone.now() - customer_otp.created_at < timezone.timedelta(minutes=2)):

                    if customer_otp.otp == otp:
                        special_characters = r"[\$#@!\*]"

                        if len(new_password) < 8 or len(new_password) > 20:
                            return CustomBadRequest(message=PASSWORD_LENGTH_SHOULD_BE_BETWEEN_8_TO_20)
                        elif re.search('[0-9]', new_password) is None:
                            return CustomBadRequest(message=PASSWORD_MUST_HAVE_ONE_NUMBER)
                        elif re.search('[a-z]', new_password) is None:
                            return CustomBadRequest(message=PASSWORD_MUST_HAVE_ONE_SMALLERCASE_LETTER)
                        elif re.search('[A-Z]', new_password) is None:
                            return CustomBadRequest(message=PASSWORD_MUST_HAVE_ONE_UPPERCASE_LETTER)
                        elif re.search(special_characters, new_password) is None:
                            return CustomBadRequest(message=PASSWORD_MUST_HAVE_ONE_SPECIAL_CHARACTER)

                        request.data["password"] = new_password

                        if reset_password_serializer.is_valid():
                            reset_password_serializer.update(customer, reset_password_serializer.validated_data)
                            return GenericSuccessResponse(message=YOUR_PASSWORD_UPDATED_SUCCESSFULLY)
                    else:
                        return CustomBadRequest(message=OTP_DOESNT_MATCH)
                else:
                    return CustomBadRequest(message=OTP_EXPIRED)
            else:
                return CustomBadRequest(message=NEW_PASSWORD_DOESNT_MATCH)
        except Exception as e:
            traceback.print_exc(e)
            return GenericException()
