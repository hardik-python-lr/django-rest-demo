# Model imports
from app.core.models import (
    UserRole,
)


def does_permission_exist(required_role_list, user_id):
    """
    Check role-based permissions of a user.

    Given a list of required role IDs and a user ID, this function determines if the user has the required roles and returns the permission status for each role.

    Parameters:
    - required_role_list (list): List of required role IDs.
    - user_id (int): ID of the user to check permissions for.

    Returns:
    - permissions (dict): Dictionary containing the permission status for each role.
      The 'allowed' key indicates whether the user has any of the required roles.
      The remaining keys correspond to the role IDs in the `required_role_list` and indicate
      whether the user has each specific role.

    """


    # Setup the return structure
    permissions = {
        'allowed': False
    }

    # Dynamically add the required permissions to the return structure
    for role in required_role_list:
        permissions['' + str(role)] = False

    # Run query to find user roles
    user_role_queryset = UserRole.objects.filter(
        user_id=user_id
    ).values(
        'role_id'
    )

    if user_role_queryset:

        user_role_list = [i['role_id'] for i in user_role_queryset]

        # Check for common roles
        common_roles = set(user_role_list).intersection(required_role_list)

        if len(common_roles) > 0:
            permissions['allowed'] = True

            for common_role in common_roles:
                permissions['' + str(common_role)] = True
    
    return permissions
