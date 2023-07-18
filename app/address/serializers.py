# Package imports
from rest_framework import serializers

# Model imports
from app.core.models import (
    Address,
)


# Start Address serializers
class AddressDisplaySerializer(serializers.ModelSerializer):
    """
    Serializer: Address Display

    This serializer is used to serialize the Address model for display purposes.

    Fields:
        - pk (int): The primary key of the address.
        - address_line_1 (str): The first line of the address.
        - address_line_2 (str): The second line of the address.
        - pincode (str): The pincode of the address.
        - city (str): The city of the address.
        - state (str): The state of the address.
        - created (datetime): The timestamp indicating the creation of the address.
        - modified (datetime): The timestamp indicating the last modification of the address.

    """

    class Meta:
        model = Address
        fields = ('pk', 'address_line_1', 'address_line_2', 'pincode', 'city', 'state', 'created', 'modified',)


class AddressCreateSerializer(serializers.ModelSerializer):
    """
    Serializer: Address Create

    This serializer is used to create a new instance of the Address model.

    Fields:
        - pk (int): The primary key of the address.
        - address_line_1 (str): The first line of the address.
        - address_line_2 (str, optional): The second line of the address.
        - pincode (str, optional): The pincode of the address.
        - city (str, optional): The city of the address.
        - state (str, optional): The state of the address.

    Additional Keyword Arguments:
        - address_line_2 (dict): Customization for the address_line_2 field (optional).
        - pincode (dict): Customization for the pincode field (optional).
        - city (dict): Customization for the city field (optional).
        - state (dict): Customization for the state field (optional).

    """

    class Meta:
        model = Address
        fields = ('pk', 'address_line_1', 'address_line_2', 'pincode', 'city', 'state',)
        extra_kwargs = {
            'address_line_2': {'required': False},
            'pincode': {'required': False},
            'city': {'required': False},
            'state': {'required': False},
        }
# End Address serializers
