# Package imports
from rest_framework import serializers

# Model imports
from app.core.models import (
    Role,
)


# Start Role serializers
class RoleDisplaySerializer(serializers.ModelSerializer):
    """
    Serializer: Role Display

    This serializer is used to serialize the Role model for display purposes.

    Fields:
        - pk (int): The primary key of the role.
        - name (str): The name of the role.

    """

    class Meta:
        model = Role
        fields = ('pk', 'name',)
# End Role serializers
