# Package imports
from rest_framework import status
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response

# Serializer imports
from app.role.serializers import (
    RoleDisplaySerializer,
)

# Model imports
from app.core.models import (
    Role
)

# Utility imports
from app.utils import (
    get_response_schema,
    get_global_error_messages,
    get_global_values,
    get_allowed_user_roles_for_create_user,
)
from app.permissions import (
    does_permission_exist
)


# Start role views
class RoleList(GenericAPIView):
    """
    View: List Role (dropdown)

    Provides an endpoint to retrieve a list of roles to be displayed as a dropdown.

    Only users with specific permissions are allowed to access this view.

    Authentication:
    - Requires JWT authentication.

    Permissions:
    - User must be authenticated.
    
    get:
        summary: Retrieve the list of roles to display as a dropdown.
        
        responses:
            200:
                description: Roles successfully retrieved.
            403:
                description: Forbidden. User does not have the required permissions.

    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Method GET: Get list of Roles to display as dropdown
        
        Retrieves a list of roles to be displayed as a dropdown.

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

        if permissions[str(get_global_values('SUPER_ADMIN_ROLE_ID'))]:
            allowed_roles = get_allowed_user_roles_for_create_user('SUPER_ADMIN_ALLOWED_ROLE_IDS')

        elif permissions[str(get_global_values('ORGANIZATION_ADMINISTRATOR_ROLE_ID'))]:
            allowed_roles = get_allowed_user_roles_for_create_user('ORGANIZATION_ADMINISTRATOR_ALLOWED_ROLE_IDS')

        elif permissions[str(get_global_values('ESTABLISHMENT_ADMIN_ROLE_ID'))]:
            allowed_roles = get_allowed_user_roles_for_create_user('ESTABLISHMENT_ADMIN_ALLOWED_ROLE_IDS')

        queryset = Role.objects.filter(
            pk__in=allowed_roles
        ).order_by(
            'pk'
        )

        role_display_serializer = RoleDisplaySerializer(queryset, many=True)

        return Response(role_display_serializer.data, status=status.HTTP_200_OK)
# End role views
