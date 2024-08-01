from common.models import Audit
from django.db import models


class Customers(Audit):
    class Meta:
        db_table = 'ee_customers'

    customer_id = models.BigAutoField(primary_key=True)
    username = models.CharField(max_length=255)

    email = models.EmailField(unique=True)
    password = models.TextField()

    mobile_no = models.CharField(max_length=50, null=True, unique=True, db_column="mobile_number")

    dob = models.DateField(db_column="usr_dob", null=True)
    credit = models.CharField(max_length=255, default="1000")


class CustomerOTP(Audit):
    class Meta:
        db_table = "ee_customer_otp"

    customer_otp_id = models.BigAutoField(primary_key=True)
    customer_id = models.ForeignKey(Customers, on_delete=models.CASCADE)
    otp = models.CharField(max_length=255)
