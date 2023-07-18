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
from app.building.serializers import (
    BuildingCreateSerializer,
    BuildingDisplaySerializer,
)

# Model imports
from app.core.models import (
    Establishment,
    Building,
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


# Start Building views
class BuildingCreate(GenericAPIView):
    """
    View: Create Building

    Provides an endpoint to create a new building.

    Only users with specific permissions are allowed to access this view.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.

    post:
        summary: Create a new building.

        responses:
            201:
                description: Building created successfully.
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
                'name': openapi.Schema(type=openapi.TYPE_STRING),
                'establishment': openapi.Schema(type=openapi.TYPE_INTEGER),
            }
        )
    )
    def post(self, request):
        """ 
        Method POST: Create Building

        Handles the HTTP POST request to create a new building.

        """

        # Check role permissions
        required_role_list = [get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, request.user.id)

        if not permissions['allowed']:
            return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        # Validating establishment ID
        establishment_queryset = Establishment.objects.filter(
            pk=request.data['establishment'],
            is_active=True,
            establishment_admin=request.user
        )

        if establishment_queryset:

            serializer = BuildingCreateSerializer(data=request.data)

            if serializer.is_valid():

                serializer.save()

                return get_response_schema(serializer.data, get_global_success_messages('RECORD_CREATED'), status.HTTP_201_CREATED)

            else:
                # BuildingCreateSerializer serializer errors
                return get_response_schema(serializer.errors, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)

        else:
            return_data = {
                settings.REST_FRAMEWORK['NON_FIELD_ERRORS_KEY']: [get_global_error_messages('SOMETHING_WENT_WRONG')]
            }
            return get_response_schema(return_data, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)


class BuildingDetail(GenericAPIView):
    """
    View: Retrieve, update or delete Building

    Provides endpoints to retrieve, update, or delete a building.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.
    - User must have the establishment admin role.

    get:
        summary: Get Building
    
        responses:
            200:
                description: Building retrieved successfully.
            403:
                description: Forbidden. User does not have the required permissions.
            404:
                description: Not Found. Building not found.

    put:
        summary: Update Building
    
        responses:
            200:
                description: Building updated successfully.
            403:
                description: Forbidden. User does not have the required permissions.
            404:
                description: Not Found. Building not found.
            400:
                description: Bad Request. Invalid request data.

    delete:
        summary: Delete Building
        
        responses:
            204:
                description: Building deleted successfully.
            403:
                description: Forbidden. User does not have the required permissions.
            404:
                description: Not Found. Building not found.
    
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self, pk, request):
        """ 
        Method: Return Building object

        Retrieves the Building object based on the provided primary key (pk) and user's request.

        """

        building_queryset = Building.objects.select_related(
            'establishment',
            'establishment__location',
            'establishment__address',
            'establishment__establishment_admin',
            'establishment__establishment_admin__user_detail',
        ).prefetch_related(
            'establishment__establishment_admin__role', 'establishment__establishment_admin__user_details__employee_categories'
        ).filter(
            pk=pk,
            is_active=True,
            establishment__establishment_admin=request.user
        )

        if building_queryset:
            return building_queryset[0]
        return None

    def get(self, request, pk=None):
        """ 
        Method GET: Get Building

        Handles the HTTP GET request to retrieve a building.

        """

        # Check role permissions
        required_role_list = [get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, request.user.id)

        if not permissions['allowed']:
            return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        building = self.get_object(pk, request)

        if building == None:    
            return get_response_schema({}, get_global_error_messages('NOT_FOUND'), status.HTTP_404_NOT_FOUND)

        serializer = BuildingDisplaySerializer(building)

        return get_response_schema(serializer.data, get_global_success_messages('RECORD_RETRIEVED'), status.HTTP_200_OK)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'name': openapi.Schema(type=openapi.TYPE_STRING),
                'establishment': openapi.Schema(type=openapi.TYPE_INTEGER),
            }
        )
    )
    def put(self, request, pk, format=None):
        """ 
        Method PUT: Update Building

        Handles the HTTP PUT request to update a building.

        """

        # Check role permissions
        required_role_list = [get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, request.user.id)

        if not permissions['allowed']:
            return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        building = self.get_object(pk, request)

        if building == None:    
            return get_response_schema({}, get_global_error_messages('NOT_FOUND'), status.HTTP_404_NOT_FOUND)

        # Validating establishment ID
        establishment_queryset = Establishment.objects.filter(
            pk=request.data['establishment'],
            is_active=True,
            establishment_admin=request.user
        )

        if establishment_queryset:

            serializer = BuildingCreateSerializer(building, data=request.data)

            if serializer.is_valid():

                serializer.save()

                return get_response_schema(serializer.data, get_global_success_messages('RECORD_UPDATED'), status.HTTP_200_OK)

            else:
                # BuildingCreateSerializer serializer errors
                return get_response_schema(serializer.errors, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)

        else:
            return_data = {
                settings.REST_FRAMEWORK['NON_FIELD_ERRORS_KEY']: [get_global_error_messages('SOMETHING_WENT_WRONG')]
            }
            return get_response_schema(return_data, get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        """ 
        Method DELETE: Delete Building

        Handles the HTTP DELETE request to delete a building.
        
        """

        # Check role permissions
        required_role_list = [get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, request.user.id)

        if not permissions['allowed']:
            return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        building = self.get_object(pk, request)

        if building == None:    
            return get_response_schema({}, get_global_error_messages('NOT_FOUND'), status.HTTP_404_NOT_FOUND)

        building.is_active = False

        building.save()

        return get_response_schema({}, get_global_success_messages('RECORD_DELETED'), status.HTTP_204_NO_CONTENT)


class BuildingList(GenericAPIView):
    """
    View: List Building (dropdown)

    Provides an endpoint to retrieve a list of buildings to display as a dropdown.

    Only users with specific permissions are allowed to access this view.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.
    
    get:
        summary: Get list of buildings to display as a dropdown.

        responses:
            200:
                description: List of buildings retrieved successfully.
            403:
                description: Forbidden. User does not have the required permissions.

    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """ 
        Method GET: Get list of Buildings to display as dropdown

        Handles the HTTP GET request to retrieve a list of buildings to display as a dropdown.

        """
        
        # Check role permissions
        required_role_list = [get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, request.user.id)

        if not permissions['allowed']:
            return get_response_schema({}, get_global_error_messages('FORBIDDEN'), status.HTTP_403_FORBIDDEN)

        queryset = Building.objects.select_related(
            'establishment',
            'establishment__location',
            'establishment__address',
            'establishment__establishment_admin',
            'establishment__establishment_admin__user_detail',
        ).prefetch_related(
            'establishment__establishment_admin__role',
            'establishment__establishment_admin__user_details__employee_categories'
        ).filter(
            is_active=True,
            establishment__establishment_admin=request.user
        ).order_by(
            'name'
        )

        building_display_serializer = BuildingDisplaySerializer(queryset, many=True)

        return Response(building_display_serializer.data, status=status.HTTP_200_OK)


class BuildingListFilter(ListAPIView):
    """
    View: List Building Filter

    Provides an endpoint to filter and display a paginated list of buildings.

    Only users with specific permissions are allowed to access this view.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.

    get:
        summary: Display paginated records.

        responses:
            200:
                description: Paginated list of buildings retrieved successfully.

    """

    serializer_class = BuildingDisplaySerializer
    pagination_class = CustomPageNumberPagination

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """ 
        Method: Return Queryset of Building

        Retrieves the queryset of buildings based on the user's request parameters.

        """

        # Check role permissions
        required_role_list = [get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID')]

        permissions = does_permission_exist(required_role_list, self.request.user.id)

        if not permissions['allowed']:
            return []

        queryset = Building.objects.select_related(
            'establishment',
            'establishment__location',
            'establishment__address',
            'establishment__establishment_admin',
            'establishment__establishment_admin__user_detail',
        ).prefetch_related(
            'establishment__establishment_admin__role',
            'establishment__establishment_admin__user_details__employee_categories'
        ).filter(
            is_active=True,
            establishment__establishment_admin=self.request.user
        ).order_by(
            'name'
        )

        if self.request.query_params.get('name'):
            queryset = queryset.filter(name__icontains=self.request.query_params.get('name'))

        return queryset

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('name', openapi.IN_QUERY, type=openapi.TYPE_STRING)
        ]
    )
    def get(self, request, *args, **kwargs):
        """ 
        Method GET: Display paginated records

        Handles the HTTP GET request to display paginated records of buildings.

        """

        return self.list(request, *args, **kwargs)
# End Building views
