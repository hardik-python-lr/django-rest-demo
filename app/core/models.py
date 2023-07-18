# Package imports
from django.conf import settings
from django.db import models
from django.contrib.auth.models import (
    BaseUserManager, 
    AbstractBaseUser, 
    PermissionsMixin
)
from django.core.validators import MinLengthValidator
from django.utils.translation import gettext_lazy as _
import uuid
import os
from django_cleanup import cleanup
from django.core.exceptions import ValidationError

INVALID_ESTABLISHMENT_SELECTION = "You can not select more than one establishment as active at same time."


# Start Common Validation Mixin
class UniqueActiveEstablishmentMixin(models.Model):
    # One User can have one establishment as ACTIVE, accordingly the Views will be worked.

    def clean(self):

        super().clean()

        if getattr(self, 'is_current_establishment', False) and self.__class__.objects.exclude(pk=self.pk).filter(user=self.user, is_current_establishment=True).exists():
            raise ValidationError(INVALID_ESTABLISHMENT_SELECTION)

    class Meta:
        abstract = True
# End Common Validation Mixin


# Start image upload configuration
def attendance_file_path(instance, filename):
    """ Generate file path for an attendance selfie file """

    # Strip the extension from the file name
    ext = filename.split('.')[-1]

    # Create the filename
    filename = f'{uuid.uuid4()}.{ext}'

    return os.path.join('uploads/attendance/', filename)


def user_image_path(instance, filename):
    """ Generate file path for an user file """

    # Strip the extension from the file name
    ext = filename.split('.')[-1]

    # Create the filename
    filename = f'{uuid.uuid4()}.{ext}'

    return os.path.join('uploads/user/', filename)
# End image upload configuration


class Role(models.Model):
    """ Model: Role """
    """ Populated by `role.json` fixture """

    # Field declarations
    name = models.CharField(max_length=255)


# Start Super-Admin related models
class UserManager(BaseUserManager):
    """ Manager: User model """

    def create_user(self, phone, password='password', **extra_fields):
        """ Create and save a new user """

        user = self.model(phone=phone, **extra_fields)
        # Set password with hash
        user.set_password(password)
        user.save(using=self._db)
        return user


    def create_superuser(self, phone, password, first_name, last_name, email):
        """ Create and save a new superuser """

        user = self.create_user(
            phone=phone,
            password='password',
            first_name=first_name,
            last_name=last_name,
            email=email,
        )
        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)
        return user


@cleanup.select
class User(AbstractBaseUser, PermissionsMixin):
    """ Model: User """

    # Key declarations
    role = models.ManyToManyField(
        'Role',
        through='UserRole',
        through_fields=('user', 'role'),
        related_name='role',
    )

    # Field declarations
    phone = models.CharField(validators=[MinLengthValidator(10)], max_length=10, unique=True)
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.EmailField(max_length=255, blank=True, null=True, unique=True)
    profile_image=models.ImageField(upload_to=user_image_path, null=True)
    # This field will be used for OTP based logic
    otp_counter = models.IntegerField(default=0, blank=True)

    is_active = models.BooleanField(default=True)

    # Additional field declarations
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)     

    # Set Django defaults
    is_superuser = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)

    # Reference custom manager
    objects = UserManager()
    # Unique identifier field - phone instead if username
    USERNAME_FIELD = 'phone'
    # Fields for superuser creation
    REQUIRED_FIELDS = ['first_name', 'last_name', 'email']

    # String representation of model
    def __str__(self):
        return self.phone


class UserDetail(models.Model):
    """ Model: UserDetail """

    # Key declarations
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='user_details',
        related_query_name='user_detail',
    )

    organization = models.ForeignKey(
        'Organization',
        on_delete=models.CASCADE,
        related_name='users',
        related_query_name='user',
        null=True,
    )

    # Additional field declarations
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)


class UserRole(models.Model):
    """ Model: UserRole (Many-To-Many through model) """

    # Key declarations
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='user_roles',
        related_query_name='user_role',
    )

    role = models.ForeignKey(
        'Role',
        on_delete=models.CASCADE,
        related_name='users',
        related_query_name='user',
    )

    # Additional field declarations
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'role',)


class Organization(models.Model):
    """ Model: Organization """

    # Key declarations
    owner_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='owned_organizations',
        related_query_name='owned_organization',
    )

    address = models.OneToOneField(
        'Address',
        on_delete=models.SET_NULL,
        related_name='organizations',
        related_query_name='organization',
        null=True,
    )

    # Field declarations
    name = models.CharField(max_length=255)

    is_active = models.BooleanField(default=True)

    # Additional field declarations
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)
# End Super-Admin related models


# Start Organization-Administrator related models
class Address(models.Model):
    """ Model: Address """

    # Field declarations
    address_line_1 = models.TextField()
    address_line_2 = models.TextField(blank=True)
    pincode = models.CharField(max_length=8, blank=True)
    city = models.CharField(max_length=255, blank=True)
    state = models.CharField(max_length=255, blank=True)

    # Additional field declarations
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)


class Location(models.Model):
    """ Model: Location """

    # Field declarations
    latitude = models.DecimalField(max_digits=22, decimal_places=16)
    longitude = models.DecimalField(max_digits=22, decimal_places=16)
    address = models.TextField()

    # Additional field declarations
    created = models.DateTimeField(auto_now_add=True)


class Establishment(models.Model):
    """ Model: Establishment """

    # ENUM declarations
    class EstablishmentType(models.TextChoices):
        RESIDENTIAL_TYPE = 'Residential', _('Residential')
        COMMERCIAL_TYPE = 'Commercial', _('Commercial')

    # Key declarations
    owner_organization = models.ForeignKey(
        'Organization',
        on_delete=models.CASCADE,
        related_name='owned_establishments',
        related_query_name='owned_establishment'
    )

    establishment_admin = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='administered_establishments',
        related_query_name='administered_establishment',
        null=True
    )

    location = models.OneToOneField(
        'Location',
        on_delete=models.SET_NULL,
        related_name='establishments',
        related_query_name='establishment',
        null=True,
    )

    address = models.OneToOneField(
        'Address',
        on_delete=models.SET_NULL,
        related_name='establishments',
        related_query_name='establishment',
        null=True,
    )

    guards = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        through='EstablishmentGuard',
        through_fields=('establishment', 'user'),
        related_name='guards',
    )

    # Field declarations
    name = models.CharField(max_length=255)
    start_date = models.DateField()
    end_date = models.DateField()

    attendance_radius = models.PositiveIntegerField()

    water_bill_link = models.TextField(blank=True)
    pipe_gas_bill_link = models.TextField(blank=True)
    electricity_bill_link = models.TextField(blank=True)

    establishment_type = models.CharField(
        max_length=20,
        choices=EstablishmentType.choices
    )

    is_active = models.BooleanField(default=True)

    # Additional field declarations
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)
# End Organization-Administrator related models


# Start Establishment-Admin related models
class EstablishmentGuard(UniqueActiveEstablishmentMixin):
    """ Model: EstablishmentGuard (Many-To-Many through model) """

    # Key declarations
    establishment = models.ForeignKey(
        'Establishment',
        on_delete=models.CASCADE,
        related_name='establishment_guards',
        related_query_name='establishment_guard'
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='guard_establishments',
        related_query_name='guard_establishment'
    )

    # Field declarations
    is_active = models.BooleanField(default=True)
    is_current_establishment = models.BooleanField(default=False)

    # Additional field declarations
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('establishment', 'user',)


class Building(models.Model):
    """ Model: Building """

    # Key declarations
    establishment = models.ForeignKey(
        'Establishment', 
        on_delete=models.CASCADE,
        related_name='buildings',
        related_query_name='building'
    )

    # Field declarations
    name = models.CharField(max_length=255)

    is_active = models.BooleanField(default=True)

    # Additional field declarations
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)


class Flat(models.Model):
    """ Model: Flat """

    # Key declarations
    building = models.ForeignKey(
        'Building', 
        on_delete=models.CASCADE,
        related_name='flats',
        related_query_name='flat'
    )

    # Field declarations
    number = models.CharField(max_length=255)
    floor_number = models.PositiveSmallIntegerField()

    is_active = models.BooleanField(default=True)

    # Additional field declarations
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)
# End Establishment-Admin related models


# Start Establishment Guard related models
@cleanup.select
class EstablishmentGuardAttendanceRecord(models.Model):
    """ Model: EstablishmentGuardAttendanceRecord """

    # Key declarations
    establishment_guard = models.ForeignKey(
        'EstablishmentGuard',
        on_delete=models.CASCADE,
        related_name='attendance_records',
        related_query_name='attendance_record',
    )
    sign_in_location = models.OneToOneField(
        'Location',
        on_delete=models.CASCADE,
        related_name='sign_in_location',
        related_query_name='sign_in_location'
    )
    sign_in_device_id = models.ForeignKey(
        'DeviceId',
        on_delete=models.SET_NULL,
        related_name='sign_in_device_ids',
        related_query_name='sign_in_device_id',
        null=True
    )
    sign_out_location = models.OneToOneField(
        'Location',
        on_delete=models.CASCADE,
        related_name='sign_out_location',
        related_query_name='sign_out_location',
        null=True
    )
    sign_out_device_id = models.ForeignKey(
        'DeviceId',
        on_delete=models.SET_NULL,
        related_name='sign_out_device_ids',
        related_query_name='sign_out_device_id',
        null=True
    )

    # Field declarations
    sign_in_image = models.ImageField(upload_to=attendance_file_path, null=True, blank=True)
    sign_in_time = models.DateTimeField()
    sign_out_time = models.DateTimeField(null=True)
    sign_out_image = models.ImageField(upload_to=attendance_file_path, null=True, blank=True)
    
    # Additional field declarations
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)


class DeviceId(models.Model):
    """ Model: DeviceId """

    # Field declarations
    device_id = models.CharField(max_length=255)

    # Additional field declarations
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)
# End Establishment Guard related models 


# Start Notification models
class PushNotificationToken(models.Model):
    """ Model: PushNotificationToken """

    # Key declarations
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='push_notification_records',
        related_query_name='push_notification_record',
    )

    # Field declarations
    device_id = models.CharField(max_length=255, blank=True)
    current_token = models.CharField(max_length=255, blank=True)

    # Additional field declarations
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)
# End Notification models
