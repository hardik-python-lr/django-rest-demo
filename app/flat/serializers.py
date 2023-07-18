# Package imports
from rest_framework import serializers

# Model imports
from app.core.models import (
    Flat
)

# Serializer imports
from app.building.serializers import (
    BuildingDisplaySerializer,
)


# Start Flat serializers
class FlatDisplaySerializer(serializers.ModelSerializer):
    """
    Serializer: Flat Display

    This serializer is used to serialize the Flat model for display purposes.

    Fields:
        - pk (int): The primary key of the flat.
        - building (BuildingDisplaySerializer): The serialized representation of the associated flat.
        - number (str): The number of the flat.
        - floor_number (int): The floor number of the flat.
        - created (datetime): The timestamp indicating the creation of the flat.
        - modified (datetime): The timestamp indicating the last modification of the flat.

    """


    building = BuildingDisplaySerializer()

    class Meta:
        model = Flat
        fields = ('pk', 'building', 'number', 'floor_number', 'created', 'modified',)


class FlatCreateSerializer(serializers.ModelSerializer):
    """
    Serializer: Flat Create

    This serializer is used for creating flats.

    Fields:
        - pk (int): The primary key of the flat.
        - building (int): The ID of the associated building.
        - number (str): The number of the flat.
        - floor_number (int): The floor number of the flat.

    """

    class Meta:
        model = Flat
        fields = ('pk', 'building', 'number', 'floor_number',)
# End Flat serializers
