# Package imports
from django.conf import settings
from rest_framework import status
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import GenericAPIView, ListAPIView
from rest_framework.response import Response

# View imports
from app.core.views import (
    CustomPageNumberPagination,
)

# Serializer imports
from app.flat.serializers import (
    FlatCreateSerializer,
    FlatDisplaySerializer,
)

# Model imports
from app.core.models import (
    Building,
    Flat,
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


# Start Flat views
class FlatCreate(GenericAPIView):
    """
    View: Create Flat

    Provides an endpoint to create a flat.

    Only users with specific permissions are allowed to access this view.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.

    post:
        summary: Create Flat
                
        responses:
            201:
                description: Flat created successfully.
            400:
                description: Bad request. Invalid or missing parameters in the request.
            403:
                description: Forbidden. User does not have the required permissions.

    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'number': openapi.Schema(type=openapi.TYPE_STRING),
                'floor_number': openapi.Schema(type=openapi.TYPE_INTEGER),
                'building': openapi.Schema(type=openapi.TYPE_INTEGER),
            }
        )
    )
    def post(self, request):
        """
        Method POST: Create Flat

        Creates a new flat with the provided information.

        """

        # Check role permissions
        required_role_list = [get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, request.user.id)

        if not permissions['allowed']:
            return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        # Validating building ID
        building_queryset = Building.objects.filter(
            pk=request.data['building'],
            is_active=True,
            establishment__establishment_admin=request.user
        )

        if building_queryset:

            serializer = FlatCreateSerializer(data=request.data)

            if serializer.is_valid():

                serializer.save()

                return get_response_schema(serializer.data, get_global_success_messages('RECORD_CREATED'), status.HTTP_201_CREATED)

            else:
                # FlatCreateSerializer serializer errors
                return get_response_schema(serializer.errors, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)

        else:
            return_data = {
                settings.REST_FRAMEWORK['NON_FIELD_ERRORS_KEY']: [get_global_error_messages('SOMETHING_WENT_WRONG')]
            }
            return get_response_schema(return_data, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)


class FlatDetail(GenericAPIView):
    """
    View: Retrieve, update or delete Flat

    Provides an endpoint to retrieve, update, or delete a flat.

    Only users with specific permissions are allowed to access this view.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.

    get:
        summary: Get Flat

        responses:
            200:
                description: Flat retrieved successfully.
            403:
                description: Forbidden. User does not have the required permissions.
            404:
                description: Not found. The flat does not exist.

    put:
        summary: Update Flat

        responses:
            200:
                description: Flat updated successfully.
            400:
                description: Bad request. Invalid or missing parameters in the request.
            403:
                description: Forbidden. User does not have the required permissions.
            404:
                description: Not found. The flat does not exist.

    delete:
        summary: Delete Flat

        responses:
            204:
                description: Flat deleted successfully.
            403:
                description: Forbidden. User does not have the required permissions.
            404:
                description: Not found. The flat does not exist.

    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self, pk, request):
        """
        Method: Return Flat object

        Retrieves the flat object based on the provided ID.

        """  

        flat_queryset = Flat.objects.select_related(
            'building__establishment',
            'building__establishment__location',
            'building__establishment__address',
            'building__establishment__establishment_admin',
            'building__establishment__establishment_admin__user_detail',
        ).prefetch_related(
            'building__establishment__establishment_admin__role', 'building__establishment__establishment_admin__user_details__employee_categories'
        ).filter(
            pk=pk,
            is_active=True,
            building__establishment__establishment_admin=request.user
        )

        if flat_queryset:
            return flat_queryset[0]
        return None

    def get(self, request, pk=None):
        """
        Method GET: Get Flat

        Retrieves the details of a specific flat.

        """

        # Check role permissions
        required_role_list = [get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, request.user.id)

        if not permissions['allowed']:
            return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        flat = self.get_object(pk, request)

        if flat == None:    
            return get_response_schema({}, get_global_error_messages('NOT_FOUND'), status.HTTP_404_NOT_FOUND)

        serializer = FlatDisplaySerializer(flat)

        return get_response_schema(serializer.data, get_global_success_messages('RECORD_RETRIEVED'), status.HTTP_200_OK)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'number': openapi.Schema(type=openapi.TYPE_STRING),
                'floor_number': openapi.Schema(type=openapi.TYPE_INTEGER),
                'building': openapi.Schema(type=openapi.TYPE_INTEGER),
            }
        )
    )
    def put(self, request, pk, format=None):
        """
        Method PUT: Update Flat

        Updates the details of a specific flat.

        """

        # Check role permissions
        required_role_list = [get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, request.user.id)

        if not permissions['allowed']:
            return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        flat = self.get_object(pk, request)

        if flat == None:    
            return get_response_schema({}, get_global_error_messages('NOT_FOUND'), status.HTTP_404_NOT_FOUND)

        # Validating building ID
        building_queryset = Building.objects.filter(
            pk=request.data['building'],
            is_active=True,
            establishment__establishment_admin=request.user
        )

        if building_queryset:

            serializer = FlatCreateSerializer(flat, data=request.data)

            if serializer.is_valid():

                serializer.save()

                return get_response_schema(serializer.data, get_global_success_messages('RECORD_UPDATED'), status.HTTP_200_OK)

            else:
                # FlatCreateSerializer serializer errors
                return get_response_schema(serializer.errors, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)

        else:
            return_data = {
                settings.REST_FRAMEWORK['NON_FIELD_ERRORS_KEY']: [get_global_error_messages('SOMETHING_WENT_WRONG')]
            }
            return get_response_schema(return_data, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        """
        Method DELETE: Delete Flat

        Deletes a specific flat.
        
        """

        # Check role permissions
        required_role_list = [get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, request.user.id)

        if not permissions['allowed']:
            return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        flat = self.get_object(pk, request)

        if flat == None:    
            return get_response_schema({}, get_global_error_messages('NOT_FOUND'), status.HTTP_404_NOT_FOUND)

        flat.is_active = False

        flat.save()

        return get_response_schema({}, get_global_success_messages('RECORD_DELETED'), status.HTTP_204_NO_CONTENT)


class FlatList(GenericAPIView):
    """
    View: List Flat (dropdown)

    Provides an endpoint to retrieve a list of flats to display as a dropdown.

    Only users with specific permissions are allowed to access this view.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.

    get:
        summary: Get list of Flats
        
        responses:
            200:
                description: List of flats retrieved successfully.
            403:
                description: Forbidden. User does not have the required permissions.

    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Method GET: Get list of Flats

        Retrieves a list of flats to display as a dropdown.

        """

        # Check role permissions
        required_role_list = [get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, request.user.id)

        if not permissions['allowed']:
            return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        queryset = Flat.objects.select_related(
            'building__establishment',
            'building__establishment__location',
            'building__establishment__address',
            'building__establishment__establishment_admin',
            'building__establishment__establishment_admin__user_detail',
        ).prefetch_related(
            'building__establishment__establishment_admin__role', 'building__establishment__establishment_admin__user_details__employee_categories'
        ).filter(
            is_active=True,
            building__establishment__establishment_admin=request.user
        ).order_by(
            'floor_number',
            'number'
        )

        flat_display_serializer = FlatDisplaySerializer(queryset, many=True)

        return Response(flat_display_serializer.data, status=status.HTTP_200_OK)


class FlatListFilter(ListAPIView):
    """
    View: List Flat Filter

    Provides an endpoint to filter and retrieve a paginated list of flats.

    Only users with specific permissions are allowed to access this view.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.

    get:
        summary: Get list of Flats with filters

        responses:
            200:
                description: List of flats retrieved successfully.
            403:
                description: Forbidden. User does not have the required permissions.

    """

    serializer_class = FlatDisplaySerializer
    pagination_class = CustomPageNumberPagination

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Method: Return object

        Returns the queryset of flats based on the provided filters.

        """

        # Check role permissions
        required_role_list = [get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, self.request.user.id)

        if not permissions['allowed']:
            return []

        queryset = Flat.objects.select_related(
            'building__establishment',
            'building__establishment__location',
            'building__establishment__address',
            'building__establishment__establishment_admin',
            'building__establishment__establishment_admin__user_detail',
        ).prefetch_related(
            'building__establishment__establishment_admin__role', 'building__establishment__establishment_admin__user_details__employee_categories'
        ).filter(
            is_active=True,
            building__establishment__establishment_admin=self.request.user
        ).order_by(
            'floor_number',
            'number'
        )

        if self.request.query_params.get('floor_number'):
            queryset = queryset.filter(floor_number=self.request.query_params.get('floor_number'))

        if self.request.query_params.get('number'):
            queryset = queryset.filter(number=self.request.query_params.get('number'))

        return queryset

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('floor_number', openapi.IN_QUERY, type=openapi.TYPE_INTEGER),
            openapi.Parameter('number', openapi.IN_QUERY, type=openapi.TYPE_INTEGER)
        ]
    )
    def get(self, request, *args, **kwargs):
        """
        Method: Display paginated records

        Retrieves and displays a paginated list of records.

        """
        
        return self.list(request, *args, **kwargs)
# End Flat views
