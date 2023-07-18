# Package imports
from rest_framework import serializers

# Model imports
from app.core.models  import (
    Establishment,
    EstablishmentGuard,
)

# Serializer imports
from app.users.serializers import (
    UserDisplaySerializer,
)
from app.location.serializers import (
    LocationDisplaySerializer,
)
from app.address.serializers import (
    AddressDisplaySerializer,
)

# Utility imports
from app.utils import (
    get_global_error_messages,
)


# Start Establishment serializers
class EstablishmentDisplaySerializer(serializers.ModelSerializer):
    """
    Serializer: Establishment Display

    This serializer is used to serialize the Establishment model for display purposes.

    Fields:
        - pk (int): The primary key of the establishment.
        - owner_organization (int): The ID of the owning organization.
        - establishment_admin (UserDisplaySerializer): The serialized representation of the associated establishment admin user.
        - location (LocationDisplaySerializer): The serialized representation of the associated establishment location.
        - address (AddressDisplaySerializer): The serialized representation of the associated establishment address.
        - name (str): The name of the establishment.
        - start_date (date): The start date of the establishment.
        - end_date (date): The end date of the establishment.
        - attendance_radius (float): The attendance radius of the establishment.
        - water_bill_link (str): The link to the water bill of the establishment.
        - pipe_gas_bill_link (str): The link to the pipe gas bill of the establishment.
        - electricity_bill_link (str): The link to the electricity bill of the establishment.
        - establishment_type (str): The type of the establishment.
        - created (datetime): The timestamp indicating the creation of the establishment.
        - modified (datetime): The timestamp indicating the last modification of the establishment.

    """

    establishment_admin = UserDisplaySerializer()
    location = LocationDisplaySerializer()
    address = AddressDisplaySerializer()

    class Meta:
        model = Establishment
        fields = ('pk', 'owner_organization', 'establishment_admin', 'location', 'address', 'name', 'start_date', 'end_date', 'attendance_radius', 'water_bill_link', 'pipe_gas_bill_link', 'electricity_bill_link', 'establishment_type', 'created', 'modified',)


class EstablishmentCreateSerializer(serializers.ModelSerializer):
    """
    Serializer: Establishment Create

    This serializer is used for creating establishments.

    Fields:
        - pk (int): The primary key of the establishment.
        - owner_organization (int): The ID of the associated owning organization.
        - location: The ID of the associated location.
        - address: The ID of the associated address.
        - name (str): The name of the establishment.
        - start_date (date): The start date of the establishment.
        - end_date (date): The end date of the establishment.
        - attendance_radius (float): The attendance radius of the establishment.
        - water_bill_link (str): The link to the water bill of the establishment.
        - pipe_gas_bill_link (str): The link to the pipe gas bill of the establishment.
        - electricity_bill_link (str): The link to the electricity bill of the establishment.
        - establishment_type (str): The type of the establishment.

    Methods:
        validate_end_date(self, value): Validates if the end_date is less than the start_date.

    """

    class Meta:
        model = Establishment
        fields = ('pk', 'owner_organization', 'location', 'address', 'name', 'start_date', 'end_date', 'attendance_radius', 'water_bill_link', 'pipe_gas_bill_link', 'electricity_bill_link', 'establishment_type',)


    def validate_end_date(self, value):
        """
        Method: Validating if end_date is less than start_date.

        """

        request = self.context.get('request')

        if not 'start_date' in request.data['establishment'] or str(value) < request.data['establishment']['start_date']:
            raise serializers.ValidationError(get_global_error_messages('INVALID_END_DATE'))

        return value
# End Establishment serializers


# Start EstablishmentAdmin serializers
class EstablishmentAdminCreateSerializer(serializers.ModelSerializer):
    """
    Serializer: EstablishmentAdmin Create

    This serializer is used for creating establishment admins.

    Fields:
        - pk (int): The primary key of the establishment.
        - establishment_admin (int): The ID of the associated establishment admin.

    """

    class Meta:
        model = Establishment
        fields = ('pk', 'establishment_admin',)
# End EstablishmentAdmin serializers


# Start EstablishmentGuard serializers
class EstablishmentGuardCreateSerializer(serializers.ModelSerializer):
    """
    Serializer: EstablishmentGuard Create

    This serializer is used for creating establishment guards.

    Fields:
        - pk (int): The primary key of the establishment guard.
        - establishment (int): The ID of the associated establishment.
        - user (int): The ID of the associated user assigned as the guard.

    """

    class Meta:
        model = EstablishmentGuard
        fields = ('pk', 'establishment', 'user',)
# End EstablishmentGuard serializers
