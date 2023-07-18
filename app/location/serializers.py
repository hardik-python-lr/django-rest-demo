# Package imports
from rest_framework import serializers

# Model imports
from app.core.models import (
    Location,
)


# Start Location serializers
class LocationDisplaySerializer(serializers.ModelSerializer):
    """
    Serializer: Location Display

    This serializer is used to serialize the Location model for display purposes.

    Fields:
        - pk (int): The primary key of the location.
        - latitude (float): The latitude coordinate of the location.
        - longitude (float): The longitude coordinate of the location.
        - address (str): The address of the location.
        - created (datetime): The timestamp indicating the creation of the location.

    """

    class Meta:
        model = Location
        fields = ('pk', 'latitude', 'longitude', 'address', 'created',)


class LocationCreateSerializer(serializers.ModelSerializer):
    """
    Serializer: Location Create

    This serializer is used for creating locations.

    Fields:
        - pk (int): The primary key of the location.
        - latitude (float): The latitude coordinate of the location.
        - longitude (float): The longitude coordinate of the location.
        - address (str): The address of the location.

    """

    class Meta:
        model = Location
        fields = ('pk', 'latitude', 'longitude', 'address',)
# End Location serializers
