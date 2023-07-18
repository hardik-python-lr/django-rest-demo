# Package imports
from django.conf import settings
from rest_framework import status
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import GenericAPIView, ListAPIView
from django.contrib.auth import (
    login, 
    get_user_model,
)
from rest_framework_simplejwt.tokens import RefreshToken
import base64
import pyotp
import os
from django.db import transaction
from rest_framework.response import Response

# View imports
from app.core.views import (
    CustomPageNumberPagination,
)

# Serializer imports
from app.users.serializers import (
    UserDisplayLoginSerializer,
    UserDisplaySerializer,
    UserCreateSerializer,
    UserDetailCreateSerializer,
    UserUpdateSerializer,

    # Organization Administrator List Filter
    OrganizationAdministratorLinkingDisplaySerializer,

    # Establishment Admin List Filter
    EstablishmentAdminLinkingDisplaySerializer,

    # Establishment Guard List Filter
    EstablishmentGuardLinkingDisplaySerializer,
)
from app.establishment.serializers import (
    EstablishmentAdminCreateSerializer,
    EstablishmentGuardCreateSerializer,
)

# Model imports
from app.core.models import (
    Organization,
    UserDetail,
    Establishment,
    EstablishmentGuard,
)

# Utility imports
from app.utils import (
    GenerateKey,
    get_response_schema,
    get_global_error_messages,
    get_global_success_messages,
    save_current_token,
    get_global_values,
    get_allowed_user_roles_for_create_user,
    get_list_intersection,
)
from app.permissions import (
    does_permission_exist
)

# Custom schema in swagger
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi


# Start authorization views
class GenerateOTPLoginView(GenericAPIView):
    """
    View: Generate OTP Login View

    Provides an endpoint to generate OTP for user login.

    Only users with specific permissions are allowed to access this view.

    post:
        summary: Generate OTP for user login.

        responses:
            200:
                description: OTP generated successfully.
            400:
                description: Bad request. Something went wrong.
            404:
                description: Not found. User not found for the provided phone number.
 
    """

    def get_object(self, phone, request):
        """
        Method: Return User object

        Retrieves the User object based on the provided phone number and active status.

        """

        user_queryset = get_user_model().objects.filter(
            phone=phone,
            is_active=True
        ).only(
            'otp_counter'
        )
        if user_queryset:
            return user_queryset[0]
        return None

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'phone': openapi.Schema(type=openapi.TYPE_STRING)
            }
        )
    )
    def post(self, request):
        """
        Method POST: Generate OTP for Login

        Generates OTP for user login based on the provided phone number.

        """

        phone = request.data['phone']

        user = self.get_object(phone, request)

        if user == None:    
            return get_response_schema({}, get_global_error_messages('NOT_FOUND'), status.HTTP_404_NOT_FOUND)

        try:
            user.otp_counter += 1

            user.save()

            otp_counter = user.otp_counter

            key_generation = GenerateKey()

            # Encoded string that will be used to create TOTP model
            # Used otp_counter based logic so each time new OTP will be generated even though previous one was not expired.
            key = base64.b32encode(key_generation.returnBaseString(phone, otp_counter).encode())

            OTP = pyotp.TOTP(key, digits = 6, interval = float(os.environ.get('OTP_EXPIRY_TIME')))

            return_data = {
                'otp': str(OTP.now())
            }

            return get_response_schema(return_data, get_global_success_messages('OTP_GENERATED'), status.HTTP_200_OK)
        except Exception as e:
            return_data = {
                settings.REST_FRAMEWORK['NON_FIELD_ERRORS_KEY']: [get_global_error_messages('SOMETHING_WENT_WRONG')]
            }
            return get_response_schema(return_data, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)


class VerifyOTPLoginView(GenericAPIView):
    """
    View: Verify OTP Login View

    Provides an endpoint to verify the OTP for user login.

    post:
        summary: Verify the OTP for user login.
        
        responses:
            200:
                description: OTP verification successful. User logged in.
            400:
                description: Bad request. OTP mismatch or something went wrong.
            404:
                description: Not found. User not found for the provided phone number.
    
    """

    def get_object(self, phone, request):
        """
        Method: Return User object

        Retrieves the User object based on the provided phone number and active status.

        """
        
        user_queryset = get_user_model().objects.prefetch_related(
            'user_details__user_employee_categories'
        ).filter(
            phone=phone,
            is_active=True
        )
        if user_queryset:
            return user_queryset[0]
        return None

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'phone': openapi.Schema(type=openapi.TYPE_STRING),
                'otp': openapi.Schema(type=openapi.TYPE_STRING)
            }
        )
    )
    def post(self, request):
        """
        Method POST: Verify OTP for Login

        Verifies the OTP for user login based on the provided phone number and OTP.

        """

        if ('phone' not in request.data.keys()) or ('otp' not in request.data.keys()):
            return_data = {
                settings.REST_FRAMEWORK['NON_FIELD_ERRORS_KEY']: [get_global_error_messages('INVALID_RESPONSE')]
            }
            return get_response_schema(return_data, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)

        phone = request.data['phone']

        user = self.get_object(phone, request)

        if user == None:    
            return get_response_schema({}, get_global_error_messages('NOT_FOUND'), status.HTTP_404_NOT_FOUND)

        try:
            otp_counter = user.otp_counter

            key_generation = GenerateKey()

            # Encoded string that will be used to create TOTP model
            # Used otp_counter based logic so each time new OTP will be generated even though previous one was not expired.
            key = base64.b32encode(key_generation.returnBaseString(phone, otp_counter).encode())

            OTP = pyotp.TOTP(key, digits = 6, interval = float(os.environ.get('OTP_EXPIRY_TIME')))

            if OTP.verify(request.data['otp']):
                login(request, user)

                # Save the Device Token for Push Notification
                try:
                    push_notification_token_obj = save_current_token(user, request.data['current_token'])

                    current_token = push_notification_token_obj.current_token
                except:
                    current_token = None

                # Get token details
                refresh = RefreshToken.for_user(user)

                # Get user details
                user_data = UserDisplayLoginSerializer(user)

                return_data = {
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'user': user_data.data,
                    'current_token': current_token
                }

                return get_response_schema(return_data, get_global_success_messages('CREDENTIALS_MATCHED'), status.HTTP_200_OK)
            
            return_data = {
                settings.REST_FRAMEWORK['NON_FIELD_ERRORS_KEY']: [get_global_error_messages('OTP_MISMATCH')]
            }
            return get_response_schema(return_data, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return_data = {
                settings.REST_FRAMEWORK['NON_FIELD_ERRORS_KEY']: [get_global_error_messages('SOMETHING_WENT_WRONG')]
            }
            return get_response_schema(return_data, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)


class CustomLogoutView(GenericAPIView):
    """
    View: Custom User Logout

    Provides an endpoint to log out the user.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.

    post:
        summary: Logout the user.
       
        responses:
            200:
                description: User successfully logged out.

    """

    authentication_classes = [JWTAuthentication,]
    permission_classes = [IsAuthenticated,]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type='object',
            properties={
                'refresh_token': openapi.Schema(type='string')
            }
        )
    )
    def post(self, request):
        """
        Method POST: Logout

        Logs out the user by blacklisting the provided refresh token.

        """
        
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return get_response_schema({}, get_global_success_messages('CREDENTIALS_REMOVED'), status.HTTP_200_OK)
        except:
            return get_response_schema({}, get_global_success_messages('CREDENTIALS_REMOVED'), status.HTTP_200_OK)
# End authorization views


# Start temporary views
class SuperAdminUserSetup(GenericAPIView):
    """
    View: Create the initial super admin user. Comment out after initial usage.

    post:
        summary: Create the initial super admin user.
        
        responses:
            201:
                description: Super admin user created successfully.
            400:
                description: Bad request. Invalid data provided.

    """

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'first_name': openapi.Schema(type=openapi.TYPE_STRING),
                'last_name': openapi.Schema(type=openapi.TYPE_STRING),
                'phone': openapi.Schema(type=openapi.TYPE_STRING),
                'email': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_EMAIL),
                'profile_image': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_BASE64)
            },
        )
    )
    def post(self, request):
        """
        Method POST: Create a SuperUser

        Creates the initial super admin user based on the provided data.

        """

        request.data['role'] = [get_global_values('SUPER_ADMIN_ROLE_ID')]

        serializer = UserCreateSerializer(data=request.data)

        if serializer.is_valid():

            serializer.save()

            return get_response_schema(serializer.data, get_global_success_messages('RECORD_CREATED'), status.HTTP_201_CREATED)

        return get_response_schema(serializer.errors, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)
# End temporary views


# Start user management views
class UserCreate(GenericAPIView):
    """
    View: Create User

    Provides an endpoint to create a new user.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.
    - User must have the required role permissions.

    post:
        summary: Create a new user.
        
        responses:
            201:
                description: User created successfully.
            400:
                description: Bad request. Invalid data provided or no valid role selected.
            403:
                description: Forbidden. User does not have the required permissions.
    
    """

    authentication_classes = [JWTAuthentication,]
    permission_classes = [IsAuthenticated,]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'first_name': openapi.Schema(type=openapi.TYPE_STRING),
                'last_name': openapi.Schema(type=openapi.TYPE_STRING),
                'phone': openapi.Schema(type=openapi.TYPE_STRING),
                'email': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_EMAIL),
                'profile_image': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_BASE64),
                'role': openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(type=openapi.TYPE_INTEGER)
                ),
            },
        )
    )
    def post(self, request):
        """
        Method POST: Create User

        Creates a new user based on the provided data and role.

        """

        # Check role permissions
        required_role_list = [get_global_values('SUPER_ADMIN_ROLE_ID'), get_global_values('ORGANIZATION_ADMINISTRATOR_ROLE_ID'), get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, request.user.id)

        if not permissions['allowed']:
            return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        final_user_role_list = []

        if permissions[str(get_global_values('SUPER_ADMIN_ROLE_ID'))]:
            allowed_roles = get_allowed_user_roles_for_create_user('SUPER_ADMIN_ALLOWED_ROLE_IDS')

        if permissions[str(get_global_values('ORGANIZATION_ADMINISTRATOR_ROLE_ID'))]:
            allowed_roles = get_allowed_user_roles_for_create_user('ORGANIZATION_ADMINISTRATOR_ALLOWED_ROLE_IDS')

        if permissions[str(get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID'))]:
            allowed_roles = get_allowed_user_roles_for_create_user('ESTABLISHMENT_ADMIN_ALLOWED_ROLE_IDS')

        initial_roles = request.data['role']

        final_user_role_list = get_list_intersection(initial_roles, allowed_roles)

        # Check if the final organization type role list has elements in it
        if len(final_user_role_list) == 0:
            return_data = {
                settings.REST_FRAMEWORK['NON_FIELD_ERRORS_KEY']: ['You must select at least one valid role for this user.']
            }
            return get_response_schema(return_data, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)

        request.data['role'] = final_user_role_list

        serializer = UserCreateSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()

            return get_response_schema(serializer.data, get_global_success_messages('RECORD_CREATED'), status.HTTP_201_CREATED)

        return get_response_schema(serializer.errors, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)


class UserDetails(GenericAPIView):
    """
    View: Retrieve, update or delete a User

    Provides endpoints to retrieve, update, or delete a user.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.
    - User must have the required role permissions.

    get:
        summary: Retrieve user.
 
        responses:
            200:
                description: User retrieved successfully.
            403:
                description: Forbidden. User does not have the required permissions.
            404:
                description: Not found. User not found.

    patch:
        summary: Update user.

        responses:
            200:
                description: User updated successfully.
            400:
                description: Bad request. Invalid data provided or no valid role selected.
            403:
                description: Forbidden. User does not have the required permissions.
            404:
                description: Not found. User not found.

    delete:
        summary: Delete user.

        responses:
            204:
                description: User deleted successfully.
            403:
                description: Forbidden. User does not have the required permissions.
            404:
                description: Not found. User not found.
   
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self, pk, request, permissions):
        """
        Method: Return User object

        Retrieves the User object based on the provided user ID, request, and permissions.

        """

        user_queryset = get_user_model().objects.prefetch_related(
            'user_details__user_employee_categories',
            'user_roles'
        ).filter(
            pk=pk,
            is_active=True
        )

        is_self_requested_user=False

        # When User request them self
        if str(pk) == str(request.user.id):
            user_queryset = get_user_model().objects.select_related(
                'user_detail'
            ).prefetch_related(
                'user_details__employee_categories',
                'role'
            ).filter(
                pk=pk,
                is_active=True
            )

            is_self_requested_user=True

        # Query when Super Admin request for Organization Administrator role user
        elif (permissions[str(get_global_values('SUPER_ADMIN_ROLE_ID'))]):

            user_queryset = user_queryset.filter(
                user_role__role__id__in=get_allowed_user_roles_for_create_user('SUPER_ADMIN_ALLOWED_ROLE_IDS'),
            )

        # Query when Organization Administrator request for Employee role user
        elif (permissions[str(get_global_values('ORGANIZATION_ADMINISTRATOR_ROLE_ID'))]):

            user_queryset = user_queryset.filter(user_role__role__id__in=get_allowed_user_roles_for_create_user('ORGANIZATION_ADMINISTRATOR_ALLOWED_ROLE_IDS'))

        # Query when Establishment Admin request for Management Committee role user
        elif (permissions[str(get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID'))]):

            user_queryset = user_queryset.filter(user_role__role__id__in=get_allowed_user_roles_for_create_user('ESTABLISHMENT_ADMIN_ALLOWED_ROLE_IDS'))

        if user_queryset != None and user_queryset:
            permissions['model'] = user_queryset[0]
            permissions['is_self_requested_user'] = is_self_requested_user
            return permissions

        return None

    def get(self, request, pk=None):
        """
        Method GET: Get user

        Retrieves the user based on the provided user ID.

        """

        required_role_list = [ 
            get_global_values('SUPER_ADMIN_ROLE_ID'), 
            get_global_values('ORGANIZATION_ADMINISTRATOR_ROLE_ID'), 
            get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID'), 
            get_global_values('SECURITY_GUARD_ROLE_ID'),  
        ]

        # Check role permissions
        user_permissions = does_permission_exist(required_role_list, request.user.id)

        if not user_permissions['allowed']:
            return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        permissions = self.get_object(pk, request, user_permissions)

        if permissions == None:    
            return get_response_schema({}, get_global_error_messages('NOT_FOUND'), status.HTTP_404_NOT_FOUND)

        serializer = UserDisplaySerializer(permissions['model'])

        return get_response_schema(serializer.data, get_global_success_messages('RECORD_RETRIEVED'), status.HTTP_200_OK)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'first_name': openapi.Schema(type=openapi.TYPE_STRING),
                'last_name': openapi.Schema(type=openapi.TYPE_STRING),
                'phone': openapi.Schema(type=openapi.TYPE_STRING),
                'email': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_EMAIL),
                'profile_image': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_BASE64),
                'role': openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(type=openapi.TYPE_INTEGER)
                ),
            },
        )
    )
    def patch(self, request, pk, format=None):
        """
        Method PATCH: Update user

        Updates the user based on the provided user ID and data.

        """

        with transaction.atomic():

            required_role_list = [ 
                get_global_values('SUPER_ADMIN_ROLE_ID'), 
                get_global_values('ORGANIZATION_ADMINISTRATOR_ROLE_ID'), 
                get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID'), 
                get_global_values('SECURITY_GUARD_ROLE_ID'),  
            ]

            # Check role permissions
            user_permissions = does_permission_exist(required_role_list, request.user.id)

            if not user_permissions['allowed']:
                return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

            permissions = self.get_object(pk, request, user_permissions)

            if permissions == None:    
                return get_response_schema({}, get_global_error_messages('NOT_FOUND'), status.HTTP_404_NOT_FOUND)

            # Retrieve the model
            user = permissions['model']

            if str(pk) == str(request.user.id):
                final_user_role_list = list(user.role.all().values_list('id', flat=True))

            elif permissions[str(get_global_values('SUPER_ADMIN_ROLE_ID'))]:
                allowed_roles = get_allowed_user_roles_for_create_user('SUPER_ADMIN_ALLOWED_ROLE_IDS')

            elif permissions[str(get_global_values('ORGANIZATION_ADMINISTRATOR_ROLE_ID'))]:
                allowed_roles = get_allowed_user_roles_for_create_user('ORGANIZATION_ADMINISTRATOR_ALLOWED_ROLE_IDS')

            elif permissions[str(get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID'))]:
                allowed_roles = get_allowed_user_roles_for_create_user('ESTABLISHMENT_ADMIN_ALLOWED_ROLE_IDS')

            try:
                initial_roles = request.data['role']

                final_user_role_list = get_list_intersection(initial_roles, allowed_roles)

                # Check if the final organization type role list has elements in it
                if len(final_user_role_list) == 0:
                    return_data = {
                        settings.REST_FRAMEWORK['NON_FIELD_ERRORS_KEY']: ['You must select at least one valid role for this user.']
                    }
                    return get_response_schema(return_data, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)
            except:
                final_user_role_list = []

            serializer = UserUpdateSerializer(user, data=request.data, context={'pk': pk, 'final_user_role_list': final_user_role_list, 'is_self_requested_user':permissions['is_self_requested_user']}, partial=True)

            if serializer.is_valid():
                serializer.save()

                return get_response_schema(serializer.data, get_global_success_messages('RECORD_UPDATED'), status.HTTP_200_OK)

            return get_response_schema(serializer.errors, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        """
        Method DELETE: Delete User

        Deletes the user based on the provided user ID.

        """


        required_role_list = [ 
            get_global_values('SUPER_ADMIN_ROLE_ID'), 
            get_global_values('ORGANIZATION_ADMINISTRATOR_ROLE_ID'), 
            get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID'),
        ]

        # Check role permissions
        user_permissions = does_permission_exist(required_role_list, request.user.id)

        if not user_permissions['allowed']:
            return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        permissions = self.get_object(pk, request, user_permissions)

        if permissions == None:    
            return get_response_schema({}, get_global_error_messages('NOT_FOUND'), status.HTTP_404_NOT_FOUND)

        # Retrieve the model
        user = permissions['model']

        user.is_active = False

        # Custom logic for preventing data loose
        # UserID + - + Old Email
        if user.email != None and user.email != '':
            user.email = str(user.id) + "-" + user.email
        else:
            user.email = None

        # UserID + add 0 for remaining places till phone number's length is 10
        user.phone = str(user.id) + "0"*(10 - len(str(user.id)))

        user.save()

        return get_response_schema({}, get_global_success_messages('RECORD_DELETED'), status.HTTP_204_NO_CONTENT)


class UserList(GenericAPIView):
    """
    View: List User (dropdown)

    Provides an endpoint to retrieve a list of users for display as a dropdown.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.
    - User must have the required role permissions.

    get:
        summary: Get list of Users to display as dropdown.
        
        responses:
            200:
                description: Users retrieved successfully.
            400:
                description: Bad request. Invalid role or missing role parameter.
            403:
                description: Forbidden. User does not have the required permissions.
    
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('role', openapi.IN_QUERY, type=openapi.TYPE_INTEGER)
        ]
    )
    def get(self, request):
        """
        Method GET: Get list of Users to display as dropdown.

        Retrieves a list of users based on the provided role ID.

        """

        # Check role permissions
        required_role_list = [ 
            get_global_values('SUPER_ADMIN_ROLE_ID'),
            get_global_values('ORGANIZATION_ADMINISTRATOR_ROLE_ID'),
            get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID'),
        ]

        permissions = does_permission_exist(required_role_list, request.user.id)

        if not permissions['allowed']:
            return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        if not (request.query_params.get('role')):
            return_data = {
                settings.REST_FRAMEWORK['NON_FIELD_ERRORS_KEY']: [get_global_error_messages('INVALID_RESPONSE')]
            }
            return get_response_schema(return_data, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)

        if permissions[str(get_global_values('SUPER_ADMIN_ROLE_ID'))]:
            allowed_roles = get_allowed_user_roles_for_create_user('SUPER_ADMIN_ALLOWED_ROLE_IDS')

        elif permissions[str(get_global_values('ORGANIZATION_ADMINISTRATOR_ROLE_ID'))]:
            allowed_roles = get_allowed_user_roles_for_create_user('ORGANIZATION_ADMINISTRATOR_ALLOWED_ROLE_IDS')

        elif permissions[str(get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID'))]:
            allowed_roles = get_allowed_user_roles_for_create_user('ESTABLISHMENT_ADMIN_ALLOWED_ROLE_IDS')

        if int(request.query_params.get('role')) not in allowed_roles:
            return_data = {
                settings.REST_FRAMEWORK['NON_FIELD_ERRORS_KEY']: [get_global_error_messages('INVALID_REQUESTED_ROLE')]
            }
            return get_response_schema(return_data, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)

        queryset = get_user_model().objects.select_related(
            'user_detail'
        ).prefetch_related(
            'user_details__employee_categories',
            'role'
        ).filter(
            is_active=True,
            user_role__role__id__in=[int(request.query_params.get('role'))]
        ).order_by(
            'first_name',
            'last_name'
        )

        user_display_serializer = UserDisplaySerializer(queryset, many=True)

        return Response(user_display_serializer.data, status=status.HTTP_200_OK)


class UserListFilter(ListAPIView):
    """
    View: List User Filter

    Provides an endpoint to retrieve a filtered list of users.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.
    - User must have the required role permissions.

    get:
        summary: Display paginated records.
       
        responses:
            200:
                description: Users retrieved successfully.
    
    """

    serializer_class = UserDisplaySerializer
    pagination_class = CustomPageNumberPagination

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Method: Return queryset

        Returns the filtered queryset of users based on the provided parameters.

        """

        # Check role permissions
        required_role_list = [ 
            get_global_values('SUPER_ADMIN_ROLE_ID'),
            get_global_values('ORGANIZATION_ADMINISTRATOR_ROLE_ID'),
            get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID'),
        ]

        permissions = does_permission_exist(required_role_list, self.request.user.id)

        if not permissions['allowed']:
            return []

        if permissions[str(get_global_values('SUPER_ADMIN_ROLE_ID'))]:
            allowed_roles = get_allowed_user_roles_for_create_user('SUPER_ADMIN_ALLOWED_ROLE_IDS')

        elif permissions[str(get_global_values('ORGANIZATION_ADMINISTRATOR_ROLE_ID'))]:
            allowed_roles = get_allowed_user_roles_for_create_user('ORGANIZATION_ADMINISTRATOR_ALLOWED_ROLE_IDS')

        elif permissions[str(get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID'))]:
            allowed_roles = get_allowed_user_roles_for_create_user('ESTABLISHMENT_ADMIN_ALLOWED_ROLE_IDS')

        queryset = get_user_model().objects.select_related(
            'user_detail'
        ).prefetch_related(
            'user_details__employee_categories',
            'role'
        ).filter(
            is_active=True,
            user_role__role__id__in=allowed_roles
        ).order_by(
            'first_name',
            'last_name'
        )

        if self.request.query_params.get('first_name'):
            queryset = queryset.filter(first_name__istartswith=self.request.query_params.get('first_name'))

        if self.request.query_params.get('last_name'):
            queryset = queryset.filter(last_name__istartswith=self.request.query_params.get('last_name'))

        if self.request.query_params.get('phone'):
            queryset = queryset.filter(phone__startswith=self.request.query_params.get('phone'))

        if self.request.query_params.get('email'):
            queryset = queryset.filter(email__istartswith=self.request.query_params.get('email'))

        if self.request.query_params.get('role'):
            if int(self.request.query_params.get('role')) not in allowed_roles:
                return []
            queryset = queryset.filter(user_role__role__id__in=[self.request.query_params.get('role')])

        return queryset

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('role', openapi.IN_QUERY, type=openapi.TYPE_INTEGER)
        ]
    )
    def get(self, request, *args, **kwargs):
        """
        Method: Display paginated records

        Retrieves and returns the paginated list of filtered users.

        """

        return self.list(request, *args, **kwargs)
# End user management views


# Start Organization Administrator linking views
class OrganizationAdministratorLinkingCreate(GenericAPIView):
    """
    View: Create OrganizationAdministratorLinking

    Provides an endpoint to link a user as an Organization Administrator to an organization.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.
    - User must have the Super Admin role.

    post:
        summary: Link User as Organization Administrator to one Organization.

        responses:
            201:
                description: Organization Administrator linking record created successfully.
            400:
                description: Bad request. The provided data is invalid or the linking operation failed.
            403:
                description: Forbidden. User does not have the required permissions.

    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'user': openapi.Schema(type=openapi.TYPE_INTEGER),
                'organization': openapi.Schema(type=openapi.TYPE_INTEGER),
            }
        )
    )
    def post(self, request):
        """
        Method POST: Link User as Organization Administrator to one Organization.

        Links the provided user as an Organization Administrator to the specified organization.

        """

        # Check role permissions
        required_role_list = [get_global_values('SUPER_ADMIN_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, request.user.id)

        if not permissions['allowed']:
            return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        # Validating Organization ID
        organization_queryset = Organization.objects.filter(
            pk=request.data['organization'],
            owner_user=request.user,
            is_active=True
        )

        # Validating User ID
        user_queryset = get_user_model().objects.filter(
            pk=request.data['user'],
            is_active=True,
            user_role__role__id__in=[get_global_values('ORGANIZATION_ADMINISTRATOR_ROLE_ID')]
        )

        if organization_queryset and user_queryset:

            serializer = UserDetailCreateSerializer(data=request.data)

            if serializer.is_valid():
                serializer.save()

                return get_response_schema(serializer.data, get_global_success_messages('RECORD_CREATED'), status.HTTP_201_CREATED)

            else:
                # UserDetailCreateSerializer serializer errors
                return_data = {
                    settings.REST_FRAMEWORK['NON_FIELD_ERRORS_KEY']: [get_global_error_messages('SOMETHING_WENT_WRONG')],
                    get_global_values('ERROR_KEY'): serializer.errors
                }
                return get_response_schema(return_data, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)
        else:
            return_data = {
                settings.REST_FRAMEWORK['NON_FIELD_ERRORS_KEY']: [get_global_error_messages('SOMETHING_WENT_WRONG')]
            }
            return get_response_schema(return_data, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)


class OrganizationAdministratorLinkingDetail(GenericAPIView):
    """
    View: Retrieve or Delete a OrganizationAdministrator linking

    Provides endpoints to retrieve or delete a specific OrganizationAdministrator linking record.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.
    - User must have the Super Admin role.

    get:
        summary: Get OrganizationAdministratorLinking

        responses:
            200:
                description: OrganizationAdministratorLinking record retrieved successfully.
            403:
                description: Forbidden. User does not have the required permissions.
            404:
                description: Not found. No valid OrganizationAdministratorLinking record found.

    delete:
        summary: Delete OrganizationAdministratorLinking

        responses:
            204:
                description: OrganizationAdministratorLinking record deleted successfully.
            403:
                description: Forbidden. User does not have the required permissions.
            404:
                description: Not found. No valid OrganizationAdministratorLinking record found.

    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self, pk, request):
        """
        Method: Return UserDetail object

        Retrieves the UserDetail object based on the provided ID, owner user, and active organization.

        """

        user_details_queryset = UserDetail.objects.select_related(
            'organization',
            'organization__address',
        ).filter(
            pk=pk,
            organization__owner_user=request.user,
            organization__is_active=True,
        )

        if user_details_queryset:
            return user_details_queryset[0]
        return None

    def get(self, request, pk=None):
        """
        Method GET: Get OrganizationAdministratorLinking

        Retrieves the OrganizationAdministratorLinking record with the specified ID.

        """

        # Check role permissions
        required_role_list = [get_global_values('SUPER_ADMIN_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, request.user.id)

        if not permissions['allowed']:
            return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        user_details = self.get_object(pk, request)

        if user_details == None:    
            return get_response_schema({}, get_global_error_messages('NOT_FOUND'), status.HTTP_404_NOT_FOUND)

        serializer = OrganizationAdministratorLinkingDisplaySerializer(user_details)

        return get_response_schema(serializer.data, get_global_success_messages('RECORD_RETRIEVED'), status.HTTP_200_OK)

    def delete(self, request, pk):
        """
        Method DELETE: Delete OrganizationAdministratorLinking

        Deletes the OrganizationAdministratorLinking record with the specified ID.

        """

        # Check role permissions
        required_role_list = [get_global_values('SUPER_ADMIN_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, request.user.id)

        if not permissions['allowed']:
            return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        user_details = self.get_object(pk, request)

        if user_details == None:    
            return get_response_schema({}, get_global_error_messages('NOT_FOUND'), status.HTTP_404_NOT_FOUND)

        user_details.delete()

        return get_response_schema({}, get_global_success_messages('RECORD_DELETED'), status.HTTP_204_NO_CONTENT)


class OrganizationAdministratorLinkingListFilter(ListAPIView):
    """
    View: List Organization Administrator Linking List Filter

    Provides a filtered list of Organization Administrator Linking records.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.
    - User must have the Super Admin role.

    get:
        summary: Get filtered list of Organization Administrator Linking records

        responses:
            200:
                description: Filtered list of Organization Administrator Linking records retrieved successfully.
            403:
                description: Forbidden. User does not have the required permissions.
            400:
                description: Bad request. Invalid or missing parameters.

    """

    serializer_class = OrganizationAdministratorLinkingDisplaySerializer
    pagination_class = CustomPageNumberPagination

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Method: Return UserDetails queryset

        Retrieves the UserDetails queryset based on the provided filters.

        """


        # Check role permissions
        required_role_list = [get_global_values('SUPER_ADMIN_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, self.request.user.id)

        if not permissions['allowed']:
            return []

        if not self.request.query_params.get('user'):
            return []

        queryset = UserDetail.objects.select_related(
            'organization',
            'organization__address',
        ).filter(
            user__id=self.request.query_params.get('user'),
            user__user_role__role__id__in=[get_global_values('ORGANIZATION_ADMINISTRATOR_ROLE_ID')],
            organization__owner_user=self.request.user,
            organization__is_active=True,
        ).order_by(
            'organization__name'
        )

        if self.request.query_params.get('name'):
            queryset = queryset.filter(organization__name__icontains=self.request.query_params.get('name'))

        return queryset

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('user', openapi.IN_QUERY, type=openapi.TYPE_INTEGER),
            openapi.Parameter('name', openapi.IN_QUERY, type=openapi.TYPE_STRING),
        ]
    )
    def get(self, request, *args, **kwargs):
        """
        Method: Display paginated records

        Retrieves the paginated list of filtered Organization Administrator Linking records.

        """

        return self.list(request, *args, **kwargs)
# End Organization Administrator linking views


# Start Establishment Admin linking views
class EstablishmentAdminLinkingCreate(GenericAPIView):
    """
    View: Create EstablishmentAdminLinking

    Creates a link between a User and an Establishment, designating the User as an Establishment Admin.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.
    - User must have the Organization Administrator role.

    post:
        summary: Create EstablishmentAdminLinking

        responses:
            201:
                description: EstablishmentAdminLinking created successfully.
            403:
                description: Forbidden. User does not have the required permissions.
            400:
                description: Bad request. Invalid or missing parameters.

    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'user': openapi.Schema(type=openapi.TYPE_INTEGER),
                'establishment': openapi.Schema(type=openapi.TYPE_INTEGER),
            }
        )
    )
    def post(self, request):
        """
        Method POST: Link User as Establishment Admin to one Establishment

        Creates a link between a User and an Establishment, designating the User as an Establishment Admin.

        """

        # Check role permissions
        required_role_list = [get_global_values('ORGANIZATION_ADMINISTRATOR_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, request.user.id)

        if not permissions['allowed']:
            return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        # Validating User ID
        user_queryset = get_user_model().objects.filter(
            pk=request.data['user'],
            is_active=True,
            user_role__role__id__in=[get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID')]
        )

        # Validating Establishment ID
        establishment_queryset = Establishment.objects.filter(
            pk=request.data['establishment'],
            is_active=True,
            owner_organization=request.user.user_details.organization
        )

        if user_queryset and establishment_queryset:

            request_data = {
                'establishment_admin': request.data['user']
            }

            serializer = EstablishmentAdminCreateSerializer(establishment_queryset.first(), data=request_data)

            if serializer.is_valid():

                serializer.save()

                return_data = request.data

                return get_response_schema(return_data, get_global_success_messages('RECORD_CREATED'), status.HTTP_201_CREATED)

            else:
                # EstablishmentAdminCreateSerializer serializer errors
                return_data = {
                    settings.REST_FRAMEWORK['NON_FIELD_ERRORS_KEY']: [get_global_error_messages('SOMETHING_WENT_WRONG')],
                    get_global_values('ERROR_KEY'): serializer.errors
                }
                return get_response_schema(return_data, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)
        else:
            return_data = {
                settings.REST_FRAMEWORK['NON_FIELD_ERRORS_KEY']: [get_global_error_messages('SOMETHING_WENT_WRONG')]
            }
            return get_response_schema(return_data, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)


class EstablishmentAdminLinkingDetail(GenericAPIView):
    """
    View: Retrieve or Delete a EstablishmentAdmin linking

    Allows retrieving or deleting the linking between an Establishment and an Establishment Admin.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.
    - User must have the Organization Administrator role.

    get:
        summary: Get EstablishmentAdminLinking

        responses:
            200:
                description: EstablishmentAdminLinking retrieved successfully.
            403:
                description: Forbidden. User does not have the required permissions.
            404:
                description: Not Found. EstablishmentAdminLinking not found.

    delete:
        summary: Delete EstablishmentAdminLinking

        responses:
            204:
                description: EstablishmentAdminLinking deleted successfully.
            403:
                description: Forbidden. User does not have the required permissions.
            404:
                description: Not Found. EstablishmentAdminLinking not found.

    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self, pk, request):
        """
        Method: Return Establishment object

        Retrieves the Establishment object based on the provided ID.

        """

        establishment_queryset = Establishment.objects.select_related(
            'location',
            'address',
        ).filter(
            pk=pk,
            is_active=True,
            owner_organization=request.user.user_details.organization,
            establishment_admin__user_role__role__id__in=[get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID')],
        )

        if establishment_queryset:
            return establishment_queryset[0]
        return None

    def get(self, request, pk=None):
        """
        Method GET: Get EstablishmentAdminLinking

        Retrieves the EstablishmentAdminLinking based on the provided ID.

        """

        # Check role permissions
        required_role_list = [get_global_values('ORGANIZATION_ADMINISTRATOR_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, request.user.id)

        if not permissions['allowed']:
            return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        establishment = self.get_object(pk, request)

        if establishment == None:    
            return get_response_schema({}, get_global_error_messages('NOT_FOUND'), status.HTTP_404_NOT_FOUND)

        serializer = EstablishmentAdminLinkingDisplaySerializer(establishment)

        return get_response_schema(serializer.data, get_global_success_messages('RECORD_RETRIEVED'), status.HTTP_200_OK)

    def delete(self, request, pk):
        """
        Method DELETE: Delete EstablishmentAdminLinking

        Deletes the EstablishmentAdminLinking based on the provided ID.

        """

        # Check role permissions
        required_role_list = [get_global_values('ORGANIZATION_ADMINISTRATOR_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, request.user.id)

        if not permissions['allowed']:
            return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        establishment = self.get_object(pk, request)

        if establishment == None:    
            return get_response_schema({}, get_global_error_messages('NOT_FOUND'), status.HTTP_404_NOT_FOUND)
    
        establishment.establishment_admin = None

        establishment.save()

        return get_response_schema({}, get_global_success_messages('RECORD_DELETED'), status.HTTP_204_NO_CONTENT)


class EstablishmentAdminLinkingListFilter(ListAPIView):
    """
    View: List Establishment Admin Linking List Filter

    Allows listing and filtering of Establishment Admin Linking records.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.
    - User must have the Organization Administrator role.

    get:
        summary: List Establishment Admin Linking records

        responses:
            200:
                description: Successfully retrieved Establishment Admin Linking records.
            403:
                description: Forbidden. User does not have the required permissions.

    """

    serializer_class = EstablishmentAdminLinkingDisplaySerializer
    pagination_class = CustomPageNumberPagination

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Method: Return Establishments queryset

        Retrieves the queryset of Establishments based on the provided filters.

        """

        # Check role permissions
        required_role_list = [get_global_values('ORGANIZATION_ADMINISTRATOR_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, self.request.user.id)

        if not permissions['allowed']:
            return []

        if not self.request.query_params.get('user'):
            return []

        queryset = Establishment.objects.select_related(
            'location',
            'address',
        ).filter(
            establishment_admin__id=self.request.query_params.get('user'),
            establishment_admin__user_role__role__id__in=[get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID')],
            is_active=True,
            owner_organization=self.request.user.user_details.organization,
        ).order_by(
            'name'
        )

        if self.request.query_params.get('name'):
            queryset = queryset.filter(name__icontains=self.request.query_params.get('name'))

        if self.request.query_params.get('establishment_type'):
            queryset = queryset.filter(establishment_type=self.request.query_params.get('establishment_type'))

        return queryset

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('user', openapi.IN_QUERY, type=openapi.TYPE_INTEGER),
            openapi.Parameter('name', openapi.IN_QUERY, type=openapi.TYPE_STRING),
            openapi.Parameter('establishment_type', openapi.IN_QUERY, type=openapi.TYPE_STRING, enum=[Establishment.EstablishmentType.RESIDENTIAL_TYPE, Establishment.EstablishmentType.COMMERCIAL_TYPE]),
        ]
    )
    def get(self, request, *args, **kwargs):
        """
        Method: Display paginated records

        Retrieves and displays the paginated records of Establishment Admin Linking.

        """

        return self.list(request, *args, **kwargs)
# End Establishment Admin linking views


# Start Establishment Guard linking views
class EstablishmentGuardLinkingCreate(GenericAPIView):
    """
    View: Create EstablishmentGuardLinking

    Allows linking a User as an Establishment Guard to one Establishment.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.
    - User must have the Establishment Administrator role.

    post:
        summary: Link User as Establishment Guard to an Establishment

        responses:
            201:
                description: Successfully created the EstablishmentGuardLinking record.
            400:
                description: Bad request. Unable to create the EstablishmentGuardLinking record.
            403:
                description: Forbidden. User does not have the required permissions.

    """


    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'user': openapi.Schema(type=openapi.TYPE_INTEGER),
                'establishment': openapi.Schema(type=openapi.TYPE_INTEGER),
            }
        )
    )
    def post(self, request):
        """
        Method POST: Link User as Establishment Guard to one Establishment

        Links a User as an Establishment Guard to the specified Establishment.

        """

        # Check role permissions
        required_role_list = [get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, request.user.id)

        if not permissions['allowed']:
            return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        # Validating User ID
        user_queryset = get_user_model().objects.filter(
            pk=request.data['user'],
            is_active=True,
            user_role__role__id__in=[get_global_values('SECURITY_GUARD_ROLE_ID')]
        )

        # Validating Establishment ID
        establishment_queryset = Establishment.objects.filter(
            pk=request.data['establishment'],
            is_active=True,
            establishment_admin=request.user
        )

        # Checking if user was linked with requested establishment previously or not if yes then simply make is_active=True

        establishment_guard_queryset = EstablishmentGuard.objects.filter(
            user__id=request.data['user'],
            establishment__id=request.data['establishment'],
            is_active=False
        )

        if establishment_guard_queryset:

            establishment_guard = establishment_guard_queryset.first()

            establishment_guard.is_active = True

            establishment_guard.save()

            return_data = request.data

            return get_response_schema(return_data, get_global_success_messages('RECORD_CREATED'), status.HTTP_201_CREATED)

        if (user_queryset) and (establishment_queryset):

            serializer = EstablishmentGuardCreateSerializer(data=request.data)

            if serializer.is_valid():

                serializer.save()

                return_data = request.data

                return get_response_schema(return_data, get_global_success_messages('RECORD_CREATED'), status.HTTP_201_CREATED)

            else:
                # EstablishmentGuardCreateSerializer serializer errors
                return_data = {
                    settings.REST_FRAMEWORK['NON_FIELD_ERRORS_KEY']: [get_global_error_messages('SOMETHING_WENT_WRONG')],
                    get_global_values('ERROR_KEY'): serializer.errors
                }
                return get_response_schema(return_data, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)
        else:
            return_data = {
                settings.REST_FRAMEWORK['NON_FIELD_ERRORS_KEY']: [get_global_error_messages('SOMETHING_WENT_WRONG')]
            }
            return get_response_schema(return_data, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)


class EstablishmentGuardLinkingDetail(GenericAPIView):
    """
    View: Retrieve or Delete an EstablishmentAdmin linking

    Allows retrieving or deleting an EstablishmentGuard linking record.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.
    - User must have the Establishment Administrator role.

    get:
        summary: Retrieve an EstablishmentGuard linking

        responses:
            200:
                description: Successfully retrieved the EstablishmentGuard linking record.
            404:
                description: The specified EstablishmentGuard linking record was not found.
            403:
                description: Forbidden. User does not have the required permissions.

    delete:
        summary: Delete an EstablishmentGuard linking

        responses:
            204:
                description: The EstablishmentGuard linking record was successfully deleted.
            404:
                description: The specified EstablishmentGuard linking record was not found.
            403:
                description: Forbidden. User does not have the required permissions.

    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self, pk, request):
        """
        Method: Return EstablishmentGuard object

        Retrieves the EstablishmentGuard object based on the provided ID.

        """

        establishment_guard_queryset = EstablishmentGuard.objects.select_related(
            'establishment__location',
            'establishment__address',
        ).filter(
            pk=pk,
            is_active=True,
            establishment__establishment_admin=request.user,
            user__user_role__role__id__in=[get_global_values('SECURITY_GUARD_ROLE_ID')],
        )

        if establishment_guard_queryset:
            return establishment_guard_queryset[0]
        return None

    def get(self, request, pk=None):
        """
        Method GET: Get EstablishmentGuard

        Retrieves an EstablishmentGuard linking record.

        """

        # Check role permissions
        required_role_list = [get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, request.user.id)

        if not permissions['allowed']:
            return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        establishment_guard = self.get_object(pk, request)

        if establishment_guard == None:    
            return get_response_schema({}, get_global_error_messages('NOT_FOUND'), status.HTTP_404_NOT_FOUND)

        serializer = EstablishmentGuardLinkingDisplaySerializer(establishment_guard)

        return get_response_schema(serializer.data, get_global_success_messages('RECORD_RETRIEVED'), status.HTTP_200_OK)

    def delete(self, request, pk):
        """
        Method DELETE: Delete an EstablishmentGuard

        Deletes an EstablishmentGuard linking record.

        """

        # Check role permissions
        required_role_list = [get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, request.user.id)

        if not permissions['allowed']:
            return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        establishment_guard = self.get_object(pk, request)

        if establishment_guard == None:    
            return get_response_schema({}, get_global_error_messages('NOT_FOUND'), status.HTTP_404_NOT_FOUND)

        establishment_guard.is_active = False

        establishment_guard.save()

        return get_response_schema({}, get_global_success_messages('RECORD_DELETED'), status.HTTP_204_NO_CONTENT)


class EstablishmentGuardLinkingListFilter(ListAPIView):
    """
    View: List Establishment Guard Linking List Filter

    Allows filtering and listing Establishment Guard linking records.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.
    - User must have the Establishment Administrator role.

    get:
        summary: List Establishment Guard linking records

        responses:
            200:
                description: Successfully retrieved the paginated Establishment Guard linking records.
            403:
                description: Forbidden. User does not have the required permissions.

    """

    serializer_class = EstablishmentGuardLinkingDisplaySerializer
    pagination_class = CustomPageNumberPagination

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Method: Return EstablishmentGuards queryset

        Returns a queryset of Establishment Guard linking records based on the provided filters.

        """

        # Check role permissions
        required_role_list = [get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, self.request.user.id)

        if not permissions['allowed']:
            return []

        if not self.request.query_params.get('user'):
            return []

        queryset = EstablishmentGuard.objects.select_related(
            'establishment__location',
            'establishment__address',
        ).filter(
            user__id=self.request.query_params.get('user'),
            user__user_role__role__id__in=[get_global_values('SECURITY_GUARD_ROLE_ID')],
            is_active=True,
            establishment__establishment_admin=self.request.user,
        ).order_by(
            'establishment__name'
        )

        if self.request.query_params.get('name'):
            queryset = queryset.filter(establishment__name__icontains=self.request.query_params.get('name'))

        if self.request.query_params.get('establishment_type'):
            queryset = queryset.filter(establishment__establishment_type=self.request.query_params.get('establishment_type'))

        return queryset

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('user', openapi.IN_QUERY, type=openapi.TYPE_INTEGER),
            openapi.Parameter('name', openapi.IN_QUERY, type=openapi.TYPE_STRING),
            openapi.Parameter('establishment_type', openapi.IN_QUERY, type=openapi.TYPE_STRING, enum=[Establishment.EstablishmentType.RESIDENTIAL_TYPE, Establishment.EstablishmentType.COMMERCIAL_TYPE]),
        ]
    )
    def get(self, request, *args, **kwargs):
        """
        Method: Display paginated records

        Retrieves and lists the paginated Establishment Guard linking records.

        """

        return self.list(request, *args, **kwargs)
# End Establishment Guard linking views
