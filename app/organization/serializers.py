# Package imports
from rest_framework import serializers

# Model imports
from app.core.models  import (
    Organization,
)

# Serializer imports
from app.address.serializers import (
    AddressDisplaySerializer,
)


# Start Organization serializers
class OrganizationDisplaySerializer(serializers.ModelSerializer):
    """
    Serializer: Organization Display

    This serializer is used to serialize the Organization model for display purposes.

    Fields:
        - pk (int): The primary key of the organization.
        - address (AddressDisplaySerializer): The serialized representation of the associated address.
        - name (str): The name of the organization.
        - created (datetime): The timestamp indicating the creation of the organization.
        - modified (datetime): The timestamp indicating the last modification of the organization.

    """

    address = AddressDisplaySerializer()

    class Meta:
        model = Organization
        fields = ('pk', 'address', 'name', 'created', 'modified',)


class OrganizationCreateSerializer(serializers.ModelSerializer):
    """
    Serializer: Organization Create

    This serializer is used for creating organizations.

    Fields:
        - pk (int): The primary key of the organization.
        - owner_user (int): The ID of the associated owner user.
        - address (int): The ID of the associated address.
        - name (str): The name of the organization.

    """

    class Meta:
        model = Organization
        fields = ('pk', 'owner_user', 'address', 'name',)
# End Organization serializers
