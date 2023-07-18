# Package imports
from rest_framework import serializers
from drf_extra_fields.fields import Base64ImageField

# Model imports
from app.core.models import (
    EstablishmentGuardAttendanceRecord,
    DeviceId
)


# Start Check-In serializer
class EstablishmentGuardAttendanceRecordSerializer(serializers.ModelSerializer):
    """
    Serializer: EstablishmentGuardAttendanceRecord CheckIn and CheckOut

    This serializer is used to serialize the EstablishmentGuardAttendanceRecord model for capturing
    guard attendance check-in and check-out details.

    Fields:
        - pk (int): The primary key of the attendance record.
        - establishment_guard (int): The establishment guard associated with the attendance record.
        - sign_in_location (int): The location ID of the check-in location.
        - sign_in_device_id (int): The device ID associated with the check-in.
        - sign_out_location (int): The location ID of the check-out location (optional).
        - sign_out_device_id (int): The device ID associated with the check-out (optional).
        - sign_in_image (str): Base64 encoded check-in image.
        - sign_out_image (str, optional): Base64 encoded check-out image.
        - sign_in_time (datetime): The timestamp of the check-in.
        - sign_out_time (datetime, optional): The timestamp of the check-out.

    """
    sign_in_image = Base64ImageField()
    sign_out_image = Base64ImageField(required=False)

    class Meta:
        model = EstablishmentGuardAttendanceRecord
        fields = ('pk', 'establishment_guard', 'sign_in_location', 'sign_in_device_id', 'sign_out_location', 'sign_out_device_id', 'sign_in_image', 'sign_out_image', 'sign_in_time', 'sign_out_time',)


class DeviceIdSerializer(serializers.ModelSerializer):
    """
    Serializer: DeviceId

    This serializer is used to serialize the DeviceId model.

    Fields:
        - pk (int): The primary key of the device ID.
        - device_id (str): The unique device ID.
        - created (datetime): The timestamp indicating the creation of the device ID.
        - modified (datetime): The timestamp indicating the last modification of the device ID.

    Methods:
        create(self, validated_data): Handles the Get or Create scenario at the serializer level.

    """

    class Meta:
        model = DeviceId
        fields = ('pk', 'device_id', 'created', 'modified',)

    def create(self, validated_data):
        """
        Method: Handle Get or Create scenario at serializer level

        This method is responsible for creating a new instance of DeviceId model or retrieving
        an existing instance if the provided data matches an already saved record.

        """

        instance, _ = DeviceId.objects.get_or_create(**validated_data)
        return instance
# End Check-In serializer
