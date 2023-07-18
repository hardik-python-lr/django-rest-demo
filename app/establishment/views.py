# Package imports
from django.conf import settings
from rest_framework import status
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import GenericAPIView, ListAPIView
from rest_framework.response import Response
from django.db import transaction
from django.db.models import Prefetch

# View imports
from app.core.views import (
    CustomPageNumberPagination,
)

# Serializer imports
from app.establishment.serializers import (
    EstablishmentCreateSerializer,
    EstablishmentDisplaySerializer,
)
from app.location.serializers import (
    LocationCreateSerializer
)
from app.address.serializers import (
    AddressCreateSerializer
)

# Model imports
from app.core.models import (
    Establishment,
    UserRole,
)   

# Utility imports
from app.utils import (
    get_response_schema,
    get_global_success_messages,
    get_global_error_messages,
    get_global_values
)
from app.permissions import (
    does_permission_exist
)

# Swagger imports
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi


# Start Establishment views
class EstablishmentCreate(GenericAPIView):
    """ 
    View: Create Establishment
    
    Provides an endpoint to create a new establishment.

    Only users with specific permissions are allowed to access this view.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.

    post:
        summary: Creates a new establishment.

        responses:
            200: 
                Check-in successfully performed.
            400: 
                Bad request. Invalid or missing parameters in the request.
            403: 
                Forbidden. User does not have the required permissions.
            404: 
                Not found. No valid establishment guard record found for the user.
        
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'location': openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'latitude': openapi.Schema(type=openapi.TYPE_STRING),
                        'longitude': openapi.Schema(type=openapi.TYPE_STRING),
                        'address': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                ),
                'address': openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'address_line_1': openapi.Schema(type=openapi.TYPE_STRING),
                        'address_line_2': openapi.Schema(type=openapi.TYPE_STRING),
                        'pincode': openapi.Schema(type=openapi.TYPE_STRING),
                        'city': openapi.Schema(type=openapi.TYPE_STRING),
                        'state': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                ),
                'establishment': openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'name': openapi.Schema(type=openapi.TYPE_STRING),
                        'start_date': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_DATE),
                        'end_date': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_DATE),
                        'water_bill_link': openapi.Schema(type=openapi.TYPE_STRING),
                        'pipe_gas_bill_link': openapi.Schema(type=openapi.TYPE_STRING),
                        'electricity_bill_link': openapi.Schema(type=openapi.TYPE_STRING),
                        'attendance_radius': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'establishment_type': openapi.Schema(type=openapi.TYPE_STRING, enum=[Establishment.EstablishmentType.RESIDENTIAL_TYPE, Establishment.EstablishmentType.COMMERCIAL_TYPE])
                    }
                ),
            }
        )
    )
    def post(self, request):
        """
        Method POST: Create Establishment

        Handles the HTTP POST request to create a new establishment.

        """

        with transaction.atomic():

            # Check role permissions
            required_role_list = [get_global_values('ORGANIZATION_ADMINISTRATOR_ROLE_ID')]

            permissions = does_permission_exist(required_role_list, request.user.id)

            if not permissions['allowed']:
                return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

            if ('location' not in request.data.keys()) or ('address' not in request.data.keys()) or ('establishment' not in request.data.keys()):
                return_data = {
                    settings.REST_FRAMEWORK['NON_FIELD_ERRORS_KEY']: [get_global_error_messages('INVALID_RESPONSE')]
                }
                return get_response_schema(return_data, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)

            # Save location
            location_create_serializer = LocationCreateSerializer(data=request.data['location'])
            if location_create_serializer.is_valid():

                location_obj = location_create_serializer.save()

                # Save address
                address_create_serializer = AddressCreateSerializer(data=request.data['address'])

                if address_create_serializer.is_valid():

                    address_obj = address_create_serializer.save()

                    # Register owner_organization, location and address request
                    request.data['establishment']['owner_organization'] = request.user.user_details.organization.id
                    request.data['establishment']['location'] = location_obj.id
                    request.data['establishment']['address'] = address_obj.id

                    establishment_create_serializer = EstablishmentCreateSerializer(data=request.data['establishment'], context={'request': request})

                    if establishment_create_serializer.is_valid():

                        establishment_create_serializer.save()

                        return_data = {
                            'location': location_create_serializer.data,
                            'address': address_create_serializer.data,
                            'establishment': establishment_create_serializer.data
                        }
                        return get_response_schema(return_data, get_global_success_messages('RECORD_CREATED'), status.HTTP_201_CREATED)
                    # Establishment serializer errors
                    # Rollback the transaction
                    transaction.set_rollback(True)
                    return_data = {
                        settings.REST_FRAMEWORK['NON_FIELD_ERRORS_KEY']: [get_global_error_messages('SOMETHING_WENT_WRONG')],
                        get_global_values('ERROR_KEY'): establishment_create_serializer.errors
                    }
                    return get_response_schema(return_data, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)

                # Rollback the transaction
                transaction.set_rollback(True)
                # Address error
                return_data = {
                    settings.REST_FRAMEWORK['NON_FIELD_ERRORS_KEY']: [get_global_error_messages('INVALID_ADDRESS')]
                }

                return get_response_schema(return_data, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)    
            # Location global error
            return_data = {
                settings.REST_FRAMEWORK['NON_FIELD_ERRORS_KEY']: [get_global_error_messages('INVALID_LOCATION')]
            }

            return get_response_schema(return_data, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)


class EstablishmentDetail(GenericAPIView):
    """
    View: Retrieve, update or delete an Establishment

    Provides an endpoint to retrieve, update, or delete an establishment.

    Only users with specific permissions are allowed to access this view.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.

    get:
        summary: Get Establishment

        responses:
            200:
                description: Establishment retrieved successfully.
            403:
                description: Forbidden. User does not have the required permissions.
            404:
                description: Not found. The establishment does not exist.

    put:
        summary: Update Establishment

        responses:
            200:
                description: Establishment updated successfully.
            400:
                description: Bad request. Invalid or missing parameters in the request.
            403:
                description: Forbidden. User does not have the required permissions.
            404:
                description: Not found. The establishment does not exist.

    delete:
        summary: Delete Establishment
        
        responses:
            204:
                description: Establishment deleted successfully.
            403:
                description: Forbidden. User does not have the required permissions.
            404:
                description: Not Found. Establishment not found.

    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self, pk, request):
        """
        View: Retrieve, update or delete an Establishment

        Provides endpoints to retrieve, update, and delete an establishment.
        
        """

        # Check role permissions
        required_role_list = [get_global_values('ORGANIZATION_ADMINISTRATOR_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, request.user.id)

        if not permissions['allowed']:
            return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        establishment_queryset = Establishment.objects.select_related(
            'establishment_admin',
            'location',
            'address',
        ).prefetch_related(
            Prefetch('establishment_admin__user_roles', queryset=UserRole.objects.select_related('role')),
        ).filter(
            pk=pk,
            is_active=True,
            owner_organization=request.user.user_details.organization
        )

        if establishment_queryset:
            return establishment_queryset[0]
        return None

    def get(self, request, pk=None):
        """
        Method GET: Get Establishment

        Retrieves and returns the details of the establishment with the specified primary key (pk).

        """

        establishment = self.get_object(pk, request)

        if establishment == None:    
            return get_response_schema({}, get_global_error_messages('NOT_FOUND'), status.HTTP_404_NOT_FOUND)

        serializer = EstablishmentDisplaySerializer(establishment)

        return get_response_schema(serializer.data, get_global_success_messages('RECORD_RETRIEVED'), status.HTTP_200_OK)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'location': openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'latitude': openapi.Schema(type=openapi.TYPE_STRING),
                        'longitude': openapi.Schema(type=openapi.TYPE_STRING),
                        'address': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                ),
                'address': openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'address_line_1': openapi.Schema(type=openapi.TYPE_STRING),
                        'address_line_2': openapi.Schema(type=openapi.TYPE_STRING),
                        'pincode': openapi.Schema(type=openapi.TYPE_STRING),
                        'city': openapi.Schema(type=openapi.TYPE_STRING),
                        'state': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                ),
                'establishment': openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'name': openapi.Schema(type=openapi.TYPE_STRING),
                        'start_date': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_DATE),
                        'end_date': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_DATE),
                        'water_bill_link': openapi.Schema(type=openapi.TYPE_STRING),
                        'pipe_gas_bill_link': openapi.Schema(type=openapi.TYPE_STRING),
                        'electricity_bill_link': openapi.Schema(type=openapi.TYPE_STRING),
                        'attendance_radius': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'establishment_type': openapi.Schema(type=openapi.TYPE_STRING, enum=[Establishment.EstablishmentType.RESIDENTIAL_TYPE, Establishment.EstablishmentType.COMMERCIAL_TYPE])
                    }
                ),
            }
        )
    )
    def put(self, request, pk, format=None):
        """
        Method PUT: Update Establishment

        Updates the establishment with the specified primary key (pk) using the provided data.
        
        """

        establishment = self.get_object(pk, request)

        if establishment == None:    
            return get_response_schema({}, get_global_error_messages('NOT_FOUND'), status.HTTP_404_NOT_FOUND)

        # Check if the location has been updated
        location_create_serializer = None

        if request.data['location'] != None:

            location_create_serializer = LocationCreateSerializer(establishment.location, data=request.data['location'])

            if location_create_serializer.is_valid():
                location_create_serializer.save()
            else:
                # Location global error
                return_data = {
                    settings.REST_FRAMEWORK['NON_FIELD_ERRORS_KEY']: [get_global_error_messages('INVALID_LOCATION')]
                }

                return get_response_schema(return_data, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)

        # Check if the address has been updated
        address_create_serializer = None

        if request.data['address'] != None:

            address_create_serializer = AddressCreateSerializer(establishment.address, data=request.data['address'])

            if address_create_serializer.is_valid():
                address_create_serializer.save()
            else:
                # Location global error
                return_data = {
                    settings.REST_FRAMEWORK['NON_FIELD_ERRORS_KEY']: [get_global_error_messages('INVALID_ADDRESS')]
                }

                return get_response_schema(return_data, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)

        # Handle establishment
        request.data['establishment']['owner_organization'] = request.user.user_details.organization.id

        establishment_create_serializer = EstablishmentCreateSerializer(establishment, data=request.data['establishment'], context={'request': request})

        if establishment_create_serializer.is_valid():
            establishment_create_serializer.save()

            return_data = {
                'location': location_create_serializer.data if location_create_serializer != None else None,
                'address': address_create_serializer.data if address_create_serializer != None else None,
                'establishment': establishment_create_serializer.data
            }

            return get_response_schema(return_data, get_global_success_messages('RECORD_UPDATED'), status.HTTP_200_OK)
        return_data = {
            settings.REST_FRAMEWORK['NON_FIELD_ERRORS_KEY']: [get_global_error_messages('SOMETHING_WENT_WRONG')],
            get_global_values('ERROR_KEY'): establishment_create_serializer.errors
        }
        return get_response_schema(return_data, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        """
        Method DELETE: Delete Establishment

        Deletes the establishment with the specified primary key (pk).
        
        """

        establishment = self.get_object(pk, request)

        if establishment == None:    
            return get_response_schema({}, get_global_error_messages('NOT_FOUND'), status.HTTP_404_NOT_FOUND)

        establishment.is_active = False
        establishment.save()

        return get_response_schema({}, get_global_success_messages('RECORD_DELETED'), status.HTTP_204_NO_CONTENT)


class EstablishmentList(GenericAPIView):
    """
    View: List Establishment (dropdown)

    Provides an endpoint to retrieve a list of establishments to display as a dropdown.

    Only users with specific permissions are allowed to access this view.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.

    get:
        summary: Get List of Establishments

        responses:
            200:
                description: List of establishments retrieved successfully.

    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Method GET: Get List of Establishments

        Retrieves a list of establishments to display as a dropdown.

        """

        # Check role permissions
        required_role_list = [get_global_values('ORGANIZATION_ADMINISTRATOR_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, request.user.id)

        if not permissions['allowed']:
            return get_response_schema([], get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        queryset = Establishment.objects.select_related(
            'establishment_admin',
            'establishment_admin__user_detail',
            'location',
            'address',
        ).prefetch_related(
            'establishment_admin__role',
            'establishment_admin__user_details__employee_categories'
        ).filter(
            is_active=True,
            owner_organization=self.request.user.user_details.organization
        ).order_by(
            '-start_date'
        )

        establishment_display_serializer = EstablishmentDisplaySerializer(queryset, many=True)

        return Response(establishment_display_serializer.data, status=status.HTTP_200_OK)


class EstablishmentListFilter(ListAPIView):
    """
    View: List Establishment Filter

    Provides an endpoint to retrieve a filtered list of establishments.

    Only users with specific permissions are allowed to access this view.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.

    get:
        summary: Get Filtered List of Establishments

        responses:
            200:
                description: Filtered list of establishments retrieved successfully.

    """

    serializer_class = EstablishmentDisplaySerializer
    pagination_class = CustomPageNumberPagination

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Method: Return Establishment queryset

        Returns the queryset of establishments based on specified filters.

        """

        # Check role permissions
        required_role_list = [get_global_values('ORGANIZATION_ADMINISTRATOR_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, self.request.user.id)

        if not permissions['allowed']:
            return []

        queryset = Establishment.objects.select_related(
            'establishment_admin',
            'establishment_admin__user_detail',
            'location',
            'address',
        ).prefetch_related(
            'establishment_admin__role',
            'establishment_admin__user_details__employee_categories'
        ).filter(
            is_active=True,
            owner_organization=self.request.user.user_details.organization
        ).order_by(
            '-start_date'
        )

        if self.request.query_params.get('name'):
            queryset = queryset.filter(name__icontains=self.request.query_params.get('name'))

        if self.request.query_params.get('establishment_type'):
            queryset = queryset.filter(establishment_type=self.request.query_params.get('establishment_type'))

        return queryset

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('name', openapi.IN_QUERY, type=openapi.TYPE_STRING),
            openapi.Parameter('establishment_type', openapi.IN_QUERY, type=openapi.TYPE_STRING, enum=[Establishment.EstablishmentType.RESIDENTIAL_TYPE, Establishment.EstablishmentType.COMMERCIAL_TYPE]),
        ]
    )
    def get(self, request, *args, **kwargs):
        """
        Method: Get Filtered List of Establishments

        Retrieves a paginated list of establishments based on specified filters.

        """

        return self.list(request, *args, **kwargs)
# End Establishment views


# Start Establishment views for Establishment Admin
class EstablishmentAdminEstablishmentList(GenericAPIView):
    """
    View: List Establishment (dropdown) for Establishment Admin

    Provides an endpoint to retrieve a list of establishments for display as a dropdown menu
    for an establishment admin.

    Only users with specific permissions are allowed to access this view.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.

    get:
        summary: Get List of Establishments for Establishment Admin

        responses:
            200:
                description: List of establishments retrieved successfully.
            403:
                description: Forbidden. User does not have the required permissions.

    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('establishment_type', openapi.IN_QUERY, type=openapi.TYPE_STRING, enum=[Establishment.EstablishmentType.RESIDENTIAL_TYPE, Establishment.EstablishmentType.COMMERCIAL_TYPE]),
        ]
    )
    def get(self, request):
        """
        Method GET: Get List of Establishments for Establishment Admin

        Retrieves a list of establishments for display as a dropdown menu for an establishment admin.

        """

        # Check role permissions
        required_role_list = [get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, request.user.id)

        if not permissions['allowed']:
            return get_response_schema([], get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        queryset = Establishment.objects.select_related(
            'establishment_admin',
            'establishment_admin__user_detail',
            'location',
            'address',
        ).prefetch_related(
            'establishment_admin__role',
            'establishment_admin__user_details__employee_categories'
        ).filter(
            is_active=True,
            establishment_admin=request.user
        ).order_by(
            '-start_date'
        )

        if request.query_params.get('establishment_type'):
            queryset = queryset.filter(
                establishment_type=request.query_params.get('establishment_type')
            )

        establishment_display_serializer = EstablishmentDisplaySerializer(queryset, many=True)

        return Response(establishment_display_serializer.data, status=status.HTTP_200_OK)


class EstablishmentAdminEstablishmentListFilter(ListAPIView):
    """
    View: List Establishment Filter for Establishment Admin

    Provides an endpoint to filter and retrieve a paginated list of establishments for an establishment admin.

    Only users with specific permissions are allowed to access this view.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.

    get:
        summary: Filter and Retrieve Establishments for Establishment Admin

        responses:
            200:
                description: List of establishments retrieved successfully.
            403:
                description: Forbidden. User does not have the required permissions.

    """

    serializer_class = EstablishmentDisplaySerializer
    pagination_class = CustomPageNumberPagination

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Method: Return Establishments Queryset

        Returns a queryset of establishments based on the specified filters.

        """

        # Check role permissions
        required_role_list = [get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, self.request.user.id)

        if not permissions['allowed']:
            return []

        queryset = Establishment.objects.select_related(
            'establishment_admin',
            'establishment_admin__user_detail',
            'location',
            'address',
        ).prefetch_related(
            'establishment_admin__role',
            'establishment_admin__user_details__employee_categories'
        ).filter(
            is_active=True,
            establishment_admin=self.request.user
        ).order_by(
            '-start_date'
        )

        if self.request.query_params.get('name'):
            queryset = queryset.filter(name__icontains=self.request.query_params.get('name'))

        if self.request.query_params.get('establishment_type'):
            queryset = queryset.filter(establishment_type=self.request.query_params.get('establishment_type'))

        return queryset

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('name', openapi.IN_QUERY, type=openapi.TYPE_STRING),
            openapi.Parameter('establishment_type', openapi.IN_QUERY, type=openapi.TYPE_STRING, enum=[Establishment.EstablishmentType.RESIDENTIAL_TYPE, Establishment.EstablishmentType.COMMERCIAL_TYPE]),
        ]
    )
    def get(self, request, *args, **kwargs):
        """
        Method: Filter and Retrieve Establishments for Establishment Admin

        Retrieves a paginated list of establishments for an establishment admin, with optional filtering.

        """

        return self.list(request, *args, **kwargs)
# End Establishment views for Establishment Admin
