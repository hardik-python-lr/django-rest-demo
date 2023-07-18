# Package imports
from rest_framework import serializers

# Model imports
from app.core.models import (
    Building
)

# Serializer imports
from app.establishment.serializers import (
    EstablishmentDisplaySerializer,
)


# Start Building serializers
class BuildingDisplaySerializer(serializers.ModelSerializer):
    """
    Serializer: Building Display

    This serializer is used to serialize the Building model for display purposes.

    Fields:
        - pk (int): The primary key of the building.
        - establishment (EstablishmentDisplaySerializer): The serialized representation of the associated establishment.
        - name (str): The name of the building.
        - created (datetime): The timestamp indicating the creation of the building.
        - modified (datetime): The timestamp indicating the last modification of the building.

    """

    establishment = EstablishmentDisplaySerializer()

    class Meta:
        model = Building
        fields = ('pk', 'establishment', 'name', 'created', 'modified',)


class BuildingCreateSerializer(serializers.ModelSerializer):
    """
    Serializer: Building Create

    This serializer is used to serialize the Building model for creation purposes.

    Fields:
        - pk (int): The primary key of the building (auto-generated upon creation).
        - establishment (int): The ID of the associated establishment.
        - name (str): The name of the building.

    """

    class Meta:
        model = Building
        fields = ('pk', 'establishment', 'name',)
# End Building serializers
