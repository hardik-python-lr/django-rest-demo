# Package imports
from rest_framework.response import Response
import requests
import json
import environ
from datetime import date
from django.utils import timezone

# For distance calculation
from math import(
    radians,
    sin,
    cos,
    sqrt,
    atan2,
)

env = environ.Env()
environ.Env.read_env()

# Model imports 
from app.core.models import (
    PushNotificationToken,
    EstablishmentGuard,
    EstablishmentGuardAttendanceRecord,
)

# Serializer imports
from app.attendance.serializers import (
    EstablishmentGuardAttendanceRecordSerializer
)


def get_global_success_messages(key):
    """ 
    Utility: Get global success messages

    This function takes a key as input and retrieves the corresponding global success message.
    
    Args:
        key (str): The identifier key for the desired success message.

    Returns:
        str or None: The success message corresponding to the given key if it exists,
        otherwise None.

    Example:
        >>> print(get_global_success_messages('CREDENTIALS_MATCHED'))
        'Login successful.'
        >>> print(get_global_success_messages('RECORD_CREATED'))
        'The record was successfully created.'
        >>> print(get_global_success_messages('INVALID_KEY'))
        None

    """

    data = {
        'CREDENTIALS_MATCHED': 'Login successful.',
        'CREDENTIALS_REMOVED': 'Logout successful.',
        'RECORD_RETRIEVED': 'The record was successfully retrieved.',
        'RECORD_CREATED': 'The record was successfully created.',
        'RECORD_UPDATED': 'The record was successfully updated.',
        'RECORD_DELETED': 'The record was successfully deleted.',
        'OTP_GENERATED': 'The otp has been sent to your phone successfully.',

        'USER_CHECKIN': 'The user was successfully checked-in.',
        'USER_CHECKOUT': 'The user was successfully checked-out.',

        'HOME_SCREEN_CHECKIN_NOT_DONE': 'Not marked.',
        'HOME_SCREEN_CHECKIN_DONE': 'Check-in completed.',
        'HOME_SCREEN_CHECKOUT_DONE': 'Check-out completed.',

        'CHECKIN_NOT_DONE': 'Check-in has not been done for today.',
        'CHECKIN_DONE': 'Check-in has been done for today.',
        'CHECKOUT_DONE': 'Check-out has been done for today.',
    }   
    return data.get(key, None)


def get_global_error_messages(key):
    """ 
    Utility: Get global error messages

    This function takes a key as input and retrieves the corresponding global error message.
    
    Args:
        key (str): The identifier key for the desired error message.

    Returns:
        str or None: The error message corresponding to the given key if it exists,
        otherwise None.

    Example:
        >>> print(get_global_error_messages('OTP_MISMATCH'))
        'OTP did not matched. Please try again.'
        >>> print(get_global_error_messages('PERMISSION_DENIED'))
        'You are not allowed to access this record.'
        >>> print(get_global_error_messages('INVALID_KEY'))
        None

    """

    data = {
        'OTP_MISMATCH': 'OTP did not matched. Please try again.',
        'BAD_REQUEST': 'Bad request.',
        'NOT_FOUND': 'Resource not found.',
        'FORBIDDEN': 'Not authenticated.',
        'INVALID_END_DATE': 'The end date must be after the start date.',
        'INVALID_END_TIME': 'The end time must be after the start time.',
        'INVALID_ADDRESS': 'The address provided does not appear to be valid. Please try again.',
        'INVALID_LOCATION': 'The location provided does not appear to be valid. Please select another location and try again.',
        'INVALID_RESPONSE': 'The detail submitted does not appear to be valid. Please try again.',
        'INVALID_M2M_TRANSACTION': 'Something went wrong. Please try again.',
        'INVALID_ROLE_SELECTION': 'You have selected roles that are not permitted.',
        'INVALID_QUERY': 'Something went wrong. No data found. Please try again.',
        'PERMISSION_DENIED': 'You are not allowed to access this record.',
        'INVALID_VALUE_MSG': 'The value provided is not valid.',
        'DUPLICATE_RECORD': 'The record that you are attempting to create already exists.',
        'INVALID_DATE_TIME': 'Invalid date and time format.',
        'INVALID_GEOMAPPING': 'You are not at the required establishment\'s location.',
        'INVALID_CHECKIN': 'Please check-out first before you check-in again.',
        'REPEATED_CHECKIN': 'You are not allowed to check-in again for the day.',
        'REPEATED_CHECKOUT': 'You are not allowed to check-out again for the day.',
        'CHECKIN_REQUIRED': 'Please check-in.',
        'SOMETHING_WENT_WRONG': 'Something went wrong. Please try again.',
        'OWN_USER_CAN_NOT_DELETE': 'You can not delete yourself.',
    }
    return data.get(key, None)


def get_global_values(key):
    """
    Utility: Get global values

    This function takes a key as input and retrieves the corresponding global value.
    
    Args:
        key (str): The identifier key for the desired global value.

    Returns:
        any or None: The global value corresponding to the given key if it exists,
        otherwise None.

    Example:
        >>> print(get_global_values('SUPER_ADMIN_ROLE_ID'))
        1
        >>> print(get_global_values('ERROR_KEY'))
        'errors'
        >>> print(get_global_values('INVALID_KEY'))
        None

    """

    data = {
        'SUPER_ADMIN_ROLE_ID': 1,
        'ORGANIZATION_ADMINISTRATOR_ROLE_ID': 2,
        'ESTABLISHMENT_ADMIN_ROLE_ID': 3,
        'SECURITY_GUARD_ROLE_ID': 4,

        'M2M_ERRORS_KEY': 'M2M_errors',
        'ERROR_KEY': 'errors',
    }

    return data.get(key, None)


def get_allowed_user_roles_for_create_user(key):
    """ 
    Utility: User roles that are allowed while creating a user

    This function takes a key as input and retrieves the list of allowed user roles
    for creating a new user based on the given key.

    Args:
        key (str): The identifier key for the allowed user roles.

    Returns:
        list or None: A list of role IDs that are allowed to be assigned to a new user
        during the user creation process, if the key exists. Otherwise,
        it returns None.

    Example:
        >>> print(get_allowed_user_roles_for_create_user('SUPER_ADMIN_ALLOWED_ROLE_IDS'))
        [2]
        >>> print(get_allowed_user_roles_for_create_user('ESTABLISHMENT_ADMIN_ALLOWED_ROLE_IDS'))
        [4]
        >>> print(get_allowed_user_roles_for_create_user('INVALID_KEY'))
        None

    """

    data = {
        'SUPER_ADMIN_ALLOWED_ROLE_IDS': [2],
        'ORGANIZATION_ADMINISTRATOR_ALLOWED_ROLE_IDS': [3],
        'ESTABLISHMENT_ADMIN_ALLOWED_ROLE_IDS': [4],
        'SECURITY_GUARD_ALLOWED_ROLE_IDS': [],
    }   
    return data.get(key, None)


def get_response_schema(schema, message, status_code):
    """ 
    Utility: Standard response structure

    This function constructs a standard response structure for API responses.

    Args:
        schema (dict): The response data or payload to be included in the 'results' field.
        message (str): A descriptive message explaining the response.
        status_code (int): The HTTP status code to be included in the response.

    Returns:
        Response: An instance of the Response class containing the standardized response
        structure with 'message', 'status', and 'results' fields.

    Example:
        >>> data = {'name': 'John', 'age': 30}
        >>> response = get_response_schema(data, 'Data retrieved successfully.', 200)
        >>> print(response.status_code)
        200
        >>> print(response.data)
        {'message': 'Data retrieved successfully.', 'status': 200, 'results': {'name': 'John', 'age': 30}}

    """
    
    return Response(
        {
            'message': message,
            'status': status_code,
            'results': schema,
        }, 
        status=status_code
    )


def get_list_difference(list1, list2):
    """ 
    Utility: Get elements which are in list1 but not in list2

    This function takes two lists as input and returns a new list containing
    elements that are present in list1 but not in list2.

    Args:
        list1 (list): The first list to compare.
        list2 (list): The second list to compare.

    Returns:
        list: A new list containing elements that are in list1 but not in list2.

    Example:
        >>> list1 = [1, 2, 3, 4, 5]
        >>> list2 = [3, 5, 6, 7, 8]
        >>> result = get_list_difference(list1, list2)
        >>> print(result)
        [1, 2, 4]

    """
    
    return list(set(list1) - set(list2))


def get_list_intersection(list1, list2):
    """ 
    Utility: Get common elements from two lists

    This function takes two lists as input and returns a new list containing
    elements that are common to both list1 and list2.

    Args:
        list1 (list): The first list to compare.
        list2 (list): The second list to compare.

    Returns:
        list: A new list containing elements that are common to both list1 and list2.

    Example:
        >>> list1 = [1, 2, 3, 4, 5]
        >>> list2 = [3, 5, 6, 7, 8]
        >>> result = get_list_intersection(list1, list2)
        >>> print(result)
        [3, 5]

    """

    return list(set(list1).intersection(list2))


def save_current_token(user,current_token):
    """ 
    Utility: Save device token in its respective model

    This function saves the current device token associated with a user
    in its respective model (PushNotificationToken). If a record for the user
    already exists, it updates the existing record; otherwise, it creates a new record.

    Args:
        user (User): The user object to whom the device token belongs.
        current_token (str): The current device token to be saved.

    Returns:
        PushNotificationToken: The PushNotificationToken object representing the user's
        device token information.

    Example:
        >>> user_obj = User.objects.get(id=1)
        >>> token = "example_device_token"
        >>> saved_token_obj = save_current_token(user_obj, token)
        >>> print(saved_token_obj.user.username)
        'example_user'
        >>> print(saved_token_obj.current_token)
        'example_device_token'

    """
    
    currentToken = current_token
    
    deviceId = 'device_id'
    
    push_notification_token_obj, _ = PushNotificationToken.objects.get_or_create(user=user)
    
    push_notification_token_obj.device_id = deviceId
    
    push_notification_token_obj.current_token = currentToken
    
    push_notification_token_obj.save()

    return push_notification_token_obj


def send_notification(user,message_title,message_desc):
    """ 
    Utility: Send notification to the user

    This function sends a push notification to the specified user using their
    current device token. The notification includes a title and description.

    Args:
        user (User): The user object to whom the notification will be sent.
        message_title (str): The title of the notification.
        message_desc (str): The description or body of the notification.

    Returns:
        requests.Response or None: The response object from the notification service
        API call if successful, otherwise returns None.

    Example:
        >>> user_obj = User.objects.get(id=1)
        >>> title = "New message"
        >>> description = "You have a new message from a friend!"
        >>> response = send_notification(user_obj, title, description)
        >>> if response is not None:
        ...     print("Notification sent successfully.")
        ... else:
        ...     print("Failed to send notification.")

    """


    fcm_api = env('FCM_TOKEN')
    url = "https://fcm.googleapis.com/fcm/send"
    
    headers = {
        "Content-Type":"application/json",
        "Authorization": 'key='+fcm_api
    }
    
    try:
        user_token = PushNotificationToken.objects.get(user=user).current_token
    except Exception as e:
        return None
    
    registered_device = [user_token]
    
    payload = {
        "registration_ids" :registered_device,
        "priority" : "high",
        "notification" : {
            "body" : message_desc,
            "title" : message_title,
            "image" : "",
            "icon": "https://static.vecteezy.com/system/resources/previews/010/366/202/original/bell-icon-transparent-notification-free-png.png",
        }
    }

    result = requests.post(url,  data=json.dumps(payload), headers=headers )

    return result


class GenerateKey:
    """ Utility: For generating dynamic hybrid OTP """

    @staticmethod
    def returnBaseString(phone, counter):
        """ 
        Generating a symmetric string for OTP generation logic.

        This static method takes a phone number and a counter as input and returns
        a symmetric string based on the provided parameters, the current date,
        and a fixed string "SeccdzeKey". This string is used in the OTP generation logic.

        Args:
            phone (str): The phone number of the user for whom the OTP is being generated.
            counter (int): The OTP counter or any other numerical value used for uniqueness.

        Returns:
            str: A symmetric string containing phone, date, fixed string, and counter information.

        Example:
            >>> phone_number = '1234567890'
            >>> otp_counter = 42
            >>> base_string = GenerateKey.returnBaseString(phone_number, otp_counter)
            >>> print(base_string)
            '12345678902021-07-18SeccdzeKey42'

        """

        return str(phone) + str(date.today()) + "SeccdzeKey" + str(counter)


def check_valid_establishment_guard_record(user_obj):
    """ 
    Utility: Check valid entry for the Establishment Guard

    This function checks if a valid entry exists for the specified user as an
    Establishment Guard. It queries the database for the establishment guard records
    associated with the provided user, and if a valid record is found, it returns a
    dictionary containing information about the establishment guard and the establishment
    type they are associated with.

    Args:
        user_obj (User): The user object for whom the establishment guard record is checked.

    Returns:
        dict: A dictionary with the following keys:
            - 'allowed' (bool): True if a valid establishment guard record exists, False otherwise.
            - 'establishment_guard' (EstablishmentGuard or None): The EstablishmentGuard object if a valid record exists, or None.
            - 'establishment_type' (str or None): The establishment type associated with the establishment guard, or None.

    Example:
        >>> user_object = User.objects.get(id=1)
        >>> result = check_valid_establishment_guard_record(user_object)
        >>> if result['allowed']:
        ...     print(f"Valid establishment guard record found. Establishment type: {result['establishment_type']}")
        ... else:
        ...     print("No valid establishment guard record found.")

    """

    establishment_guard_queryset = EstablishmentGuard.objects.select_related(
        'establishment'
    ).filter(
        user=user_obj,
        is_current_establishment=True,
        is_active=True
    )

    status = {
        'allowed': False,
        'establishment_guard': None,
        'establishment_type': None
    }

    if establishment_guard_queryset.exists():

        establishment_guard = establishment_guard_queryset.first()

        status['allowed'] = True

        status['establishment_guard'] = establishment_guard

        status['establishment_type'] = establishment_guard.establishment.establishment_type

        return status

    return status


def distance_in_meter(lat1, lon1, lat2, lon2):
    """ 
    Utility: Find the distance between two points in meters

    This function calculates the distance between two geographical points
    (latitude and longitude) using the Haversine formula.

    Args:
        lat1 (float): Latitude of the first point in degrees.
        lon1 (float): Longitude of the first point in degrees.
        lat2 (float): Latitude of the second point in degrees.
        lon2 (float): Longitude of the second point in degrees.

    Returns:
        float: The distance between the two points in meters.

    Example:
        >>> lat1, lon1 = 37.7749, -122.4194
        >>> lat2, lon2 = 34.0522, -118.2437
        >>> result = distance_in_meter(lat1, lon1, lat2, lon2)
        >>> print(result)
        543828.5222507465  # Approx. 543.83 km

    """

    # Convert degrees to radians
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])

    # Haversine formula
    dlat = lat2 - lat1

    dlon = lon2 - lon1

    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2

    c = 2 * atan2(sqrt(a), sqrt(1-a))

    R = 6371  # Radius of the Earth in kilometers

    distance = R * c

    # To return the output in meters
    return distance * 1000


def attendance_marked_status(establishment_guard):
    """ 
    Utility: Check if user has done check-in or check-out

    This function checks if an attendance record exists for the specified establishment guard
    for the current date. If an attendance record is found, it returns a dictionary containing
    information about the check-in or check-out status, timestamps, and related images.

    Args:
        establishment_guard (EstablishmentGuard): The establishment guard object for whom
        the attendance status is checked.

    Returns:
        dict: A dictionary with the following keys:
            - 'attendance_status_msg' (str): The message indicating the check-in/check-out status.
            - 'sign_in_time' (datetime or None): The timestamp of check-in if available, or None.
            - 'sign_out_time' (datetime or None): The timestamp of check-out if available, or None.
            - 'sign_in_image' (str or None): The URL or path of the check-in image if available, or None.
            - 'sign_out_image' (str or None): The URL or path of the check-out image if available, or None.
            - 'is_checkin' (bool): True if check-in is done, False otherwise.
            - 'is_checkout' (bool): True if check-out is done, False otherwise.

    Example:
        >>> establishment_guard_obj = EstablishmentGuard.objects.get(id=1)
        >>> result = attendance_marked_status(establishment_guard_obj)
        >>> print(result['attendance_status_msg'])
        'Check-in has not been done for today.'
        >>> print(result['sign_in_time'])
        None
        >>> print(result['is_checkin'])
        False
        >>> print(result['is_checkout'])
        False

    """

    attendancerecord = EstablishmentGuardAttendanceRecord.objects.filter(
        establishment_guard=establishment_guard,
        sign_in_time__date=date.today()
    )

    if attendancerecord.exists():

        attendance = attendancerecord.first()

        attendance_record_serializer = EstablishmentGuardAttendanceRecordSerializer(attendance)

        if (not attendance.sign_out_location) and (not attendance.sign_out_time) and (not attendance.sign_out_device_id) and (not attendance.sign_out_image):

            attendance_status = get_global_success_messages()['CHECKIN_DONE']

            is_checkout = False

            is_checkin = True

            sign_in_time = attendance.sign_in_time

            sign_out_time = attendance.sign_out_time

            sign_in_image = attendance_record_serializer.data['sign_in_image']

            sign_out_image = attendance_record_serializer.data['sign_out_image']

        elif (attendance.sign_out_location) and (attendance.sign_out_time) and (attendance.sign_out_device_id) and (attendance.sign_out_image):

            attendance_status = get_global_success_messages()['CHECKOUT_DONE']

            is_checkout = True

            is_checkin = False

            sign_in_time = attendance.sign_in_time

            sign_out_time = attendance.sign_out_time

            sign_in_image = attendance_record_serializer.data['sign_in_image']

            sign_out_image = attendance_record_serializer.data['sign_out_image']

    else:

        attendance_status = get_global_success_messages()['CHECKIN_NOT_DONE']

        is_checkout = False

        is_checkin = False

        sign_in_time = None

        sign_out_time = None

        sign_in_image = None

        sign_out_image = None

    return_data = {
        'attendance_status_msg' : attendance_status,
        'sign_in_time' : timezone.template_localtime(sign_in_time),
        'sign_out_time' : timezone.template_localtime(sign_out_time),
        'sign_in_image' : sign_in_image,
        'sign_out_image' : sign_out_image,
        'is_checkin' : is_checkin,
        'is_checkout' : is_checkout,
    }

    return return_data
