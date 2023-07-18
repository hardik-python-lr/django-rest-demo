# Package imports
from rest_framework import serializers
from django.contrib.auth import get_user_model
import re
from drf_extra_fields.fields import Base64ImageField

# Model imports
from app.core.models import (
    Role,
    UserDetail,
    Establishment,
    EstablishmentGuard,
    Flat,
    Building
)

# Serializer imports
from app.role.serializers import (
    RoleDisplaySerializer,
)
from app.organization.serializers import (
    OrganizationDisplaySerializer
)
from app.location.serializers import (
    LocationDisplaySerializer,
)
from app.address.serializers import (
    AddressDisplaySerializer,
)

# Utility imports
from app.utils import get_global_error_messages


# Start validation helper functions
def validate_phone_helper(value, pk):
    """
    Validate phone

    Validates the given phone number and checks if it meets the required format. If a primary key (`pk`) is provided, it ensures that the phone number is unique among active users, excluding the user with the given primary key.

    """

    if value:
        valid_phone = re.search('^[0-9]{10}$', value)
        if not valid_phone:
            raise serializers.ValidationError(get_global_error_messages('INVALID_VALUE_MSG'))
        if pk == None:
            if get_user_model().objects.filter(phone=value, is_active=True).exists():
                raise serializers.ValidationError('user with this phone already exists.')
        else:
            if get_user_model().objects.filter(phone=value, is_active=True).exclude(pk=pk).exists():
                raise serializers.ValidationError('user with this phone already exists.')
        return value


def validate_email_helper(value, pk):
    """ 
    Validate email

    Validates the given email address and checks if it meets the required format. If a primary key (`pk`) is provided, it ensures that the email address is unique among active users, excluding the user with the given primary key.

    """

    if value:
        updated_value = value.lower()
        if pk == None:
            if get_user_model().objects.filter(email=updated_value, is_active=True).exists():
                raise serializers.ValidationError('user with this email already exists.')
        else:
            if get_user_model().objects.filter(email=updated_value, is_active=True).exclude(pk=pk).exists():
                raise serializers.ValidationError('user with this email already exists.')
        return updated_value
    return None
# End validation helper functions


class UserDisplaySerializer(serializers.ModelSerializer):
    """
    Serializer: User Display

    Serializes the user data for display purposes.

    Fields:
    - pk: Primary key of the user.
    - phone: Phone number of the user.
    - first_name: First name of the user.
    - last_name: Last name of the user.
    - email: Email address of the user.
    - profile_image: Profile image of the user.
    - otp_counter: Counter for OTP (One-Time Password) attempts.
    - created: Date and time when the user was created.
    - modified: Date and time when the user was last modified.
    - role: List of roles assigned to the user.

    """

    role = RoleDisplaySerializer(many=True)

    class Meta:
        model = get_user_model()
        fields = ('pk', 'phone', 'first_name', 'last_name', 'email', 'profile_image', 'otp_counter', 'created', 'modified', 'role',)


class UserDisplayLoginSerializer(serializers.ModelSerializer):
    """
    Serializer: User Display For Login

    Serializes the user data for display purposes during login.

    Fields:
    - pk: Primary key of the user.
    - phone: Phone number of the user.
    - first_name: First name of the user.
    - last_name: Last name of the user.
    - email: Email address of the user.
    - profile_image: Profile image of the user.
    - otp_counter: Counter for OTP (One-Time Password) attempts.
    - created: Date and time when the user was created.
    - modified: Date and time when the user was last modified.
    - role: List of roles assigned to the user.
    - organization(OrganizationDisplaySerializer): The serialized representation of the associated Organization.

    """

    role = RoleDisplaySerializer(many=True)
    organization = OrganizationDisplaySerializer(source='user_details.organization')

    class Meta:
        model = get_user_model()
        fields = ('pk', 'phone', 'first_name', 'last_name', 'email', 'profile_image', 'otp_counter', 'created', 'modified', 'role', 'organization',)


class UserCreateSerializer(serializers.ModelSerializer):
    """
    Serializer: User Create

    Serializes the data required for creating a new user.

    Fields:
    - pk: Primary key of the user.
    - first_name: First name of the user.
    - last_name: Last name of the user.
    - phone: Phone number of the user.
    - email: Email address of the user.
    - profile_image: Profile image of the user.
    - role: List of roles assigned to the user.

    Validation Methods:
    - validate_phone: Validates the phone number field.
    - validate_email: Validates the email field.

    Custom Create Method:
    - create: Handles the creation of a new user, including assigning roles if provided.

    """

    role = serializers.PrimaryKeyRelatedField(many=True, queryset=Role.objects.all())
    profile_image = Base64ImageField(required=False)

    class Meta:
        model = get_user_model()
        fields = ('pk', 'first_name', 'last_name', 'phone', 'email', 'profile_image', 'role',)

    def validate_phone(self, value):
        """ 
        Method: Validate phone

        Validates the provided phone number for uniqueness and format.

        """

        return validate_phone_helper(value, pk=None)

    def validate_email(self, value):
        """ 
        Method: Validate email

        Validates the provided email address for uniqueness and format.
        
        """

        return validate_email_helper(value, pk=None)

    def create(self, validated_data):
        """ 
        Method: Handle Create User's role scenario

        Creates a new user with the validated data and assigns the specified roles.

        """

        role = validated_data.pop('role', [])

        user = get_user_model().objects.create_user(**validated_data)

        if role:
            user.role.set(role)
        
        return user


class UserUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer: User Update

    Serializes the data required for updating a user.

    Fields:
    - pk: Primary key of the user.
    - first_name: First name of the user.
    - last_name: Last name of the user.
    - phone: Phone number of the user.
    - email: Email address of the user.
    - profile_image: Profile image of the user.
    - is_active: Flag indicating the user's active status.
    - role: List of roles assigned to the user.

    Initialization Method:
    - __init__: Manages dynamic fields based on the request context.

    Validation Methods:
    - validate_phone: Validates the phone number field.
    - validate_email: Validates the email field.

    Custom Update Method:
    - update: Handles the updating of a user, including assigning roles if provided.

    """

    profile_image = Base64ImageField()

    def __init__(self, *args, **kwargs):
        """ 
        Method: To manage fields dynamically from serializer

        Initializes the serializer and manages dynamic fields based on the request context. If the requested user is the self user, the phone field is set as read-only.
        
        """

        # Instantiate the superclass normally
        super(UserUpdateSerializer, self).__init__(*args, **kwargs)

        if (self.context['is_self_requested_user']):

            self.fields.get('phone').read_only = True

    class Meta:
        model = get_user_model()
        fields = ('pk', 'first_name', 'last_name', 'phone', 'email', 'profile_image', 'is_active', 'role',)

    def validate_phone(self, value):
        """ 
        Method: Validate phone

        Validates the provided phone number for uniqueness and format.
        
        """

        pk = self.context.get('pk')

        return validate_phone_helper(value, pk)

    def validate_email(self, value):
        """ 
        Method: Validate email
        
        Validates the provided email address for uniqueness and format.

        """

        pk = self.context.get('pk')

        return validate_email_helper(value, pk)


    def update(self, instance, validated_data):
        """ 
        Method: Handle Update User's role scenario

        Updates the user instance with the validated data and assigns the specified roles.

        """

        final_user_role_list = self.context.get('final_user_role_list', [])

        if final_user_role_list:
            instance.role.set(final_user_role_list)

        super().update(instance=instance, validated_data=validated_data)

        return instance


# Start UserDetail serializers
class UserDetailCreateSerializer(serializers.ModelSerializer):
    """
    Serializer: UserDetail Create

    Serializes the data required for creating a UserDetail object.

    Fields:
    - pk: Primary key of the UserDetail object.
    - user: User associated with the UserDetail.
    - organization: Organization associated with the UserDetail.

    """

    class Meta:
        model = UserDetail
        fields = ('pk', 'user', 'organization',)
# End UserDetail serializers


# Start Organization Administrator serializer
class OrganizationAdministratorLinkingDisplaySerializer(serializers.ModelSerializer):
    """
    Serializer: UserDetail Display

    Serializes the data required to display a UserDetail object in the context of an Organization Administrator linking.

    Fields:
    - pk: Primary key of the UserDetail object.
    - user: User associated with the UserDetail.
    - organization(OrganizationDisplaySerializer): The serialized representation of the associated Organization.

    """

    organization = OrganizationDisplaySerializer()

    class Meta:
        model = UserDetail
        fields = ('pk', 'user', 'organization',)
# End Organization Administrator serializer


# Start Employee serializer
class EmployeeLinkingDisplaySerializer(serializers.ModelSerializer):
    """
    Serializer: UserDetail Display

    Serializes the data required to display a UserDetail object in the context of an Employee linking.

    Fields:
    - pk: Primary key of the UserDetail object.
    - user: User associated with the UserDetail.
    - organization(OrganizationDisplaySerializer): The serialized representation of the associated Organization.

    """

    organization = OrganizationDisplaySerializer()

    class Meta:
        model = UserDetail
        fields = ('pk', 'user', 'organization',)
# End Employee serializer


# Start Establishment Admin serializer
class EstablishmentAdminLinkingDisplaySerializer(serializers.ModelSerializer):
    """
    Serializer: Establishment Display

    Serializes the data required to display an Establishment object in the context of an Establishment Admin linking.

    Fields:
    - pk: Primary key of the Establishment object.
    - owner_organization: Organization that owns the Establishment.
    - establishment_admin: User associated with the Establishment Admin.
    - location(LocationDisplaySerializer): The serialized representation of the associated location.
    - address(AddressDisplaySerializer): The serialized representation of the associated Address.
    - name: Name of the Establishment.
    - start_date: Start date of the Establishment.
    - end_date: End date of the Establishment.
    - establishment_type: Type of the Establishment.

    """

    location = LocationDisplaySerializer()
    address = AddressDisplaySerializer()

    class Meta:
        model = Establishment
        fields = ('pk', 'owner_organization', 'establishment_admin', 'location', 'address', 'name', 'start_date', 'end_date', 'establishment_type',)
# End Establishment Admin serializer


# Start Establishment Guard serializer
class EstablishmentGuardLinkingDisplaySerializer(serializers.ModelSerializer):
    """
    Serializer: Establishment Guard Display

    Serializes the data required to display an Establishment Guard object in the context of Establishment Guard linking.

    Fields:
    - pk: Primary key of the Establishment Guard object.
    - user: User associated with the Establishment Guard.
    - establishment(EstablishmentDisplaySerializer): The serialized representation of the associated Establishment.
    - is_current_establishment: Indicates if the Establishment Guard is currently linked to the establishment.

    """

    establishment = EstablishmentAdminLinkingDisplaySerializer()

    class Meta:
        model = EstablishmentGuard
        fields = ('pk', 'user', 'establishment', 'is_current_establishment',)
# End Establishment Guard serializer


# Start Resident User
class EstablishmentLinkingDisplaySerializer(serializers.ModelSerializer):
    """
    Serializer: Establishment Display

    Serializes the data required to display an Establishment object in the context of linking.

    Fields:
    - pk: Primary key of the Establishment object.
    - owner_organization: Organization that owns the Establishment.
    - establishment_admin(UserDisplaySerializer): The serialized representation of the associated User who is the administrator of the Establishment.
    - location(LocationDisplaySerializer): The serialized representation of the associated Location information of the Establishment.
    - address(AddressDisplaySerializer): The serialized representation of the associated Address information of the Establishment.
    - name: Name of the Establishment.
    - start_date: Start date of the Establishment.
    - end_date: End date of the Establishment.
    - water_bill_link: Link to the water bill associated with the Establishment.
    - pipe_gas_bill_link: Link to the pipe gas bill associated with the Establishment.
    - electricity_bill_link: Link to the electricity bill associated with the Establishment.
    - created: Date and time when the Establishment was created.
    - modified: Date and time when the Establishment was last modified.

    """

    establishment_admin = UserDisplaySerializer()
    location = LocationDisplaySerializer()
    address = AddressDisplaySerializer()

    class Meta:
        model = Establishment
        fields = ('pk', 'owner_organization', 'establishment_admin', 'location', 'address', 'name', 'start_date', 'end_date', 'water_bill_link', 'pipe_gas_bill_link', 'electricity_bill_link', 'created', 'modified',)
# End Establishment Guard serializer
