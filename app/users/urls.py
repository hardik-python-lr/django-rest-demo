from django.urls import path
from app.users.views import (
    # Authentication Flow
    GenerateOTPLoginView,
    VerifyOTPLoginView,
    CustomLogoutView,

    # Create initial super admin user
    SuperAdminUserSetup,

    # User management Flow
    UserCreate,
    UserDetails,
    UserList,
    UserListFilter,

    # Organization Administrator
    OrganizationAdministratorLinkingCreate,
    OrganizationAdministratorLinkingDetail,
    OrganizationAdministratorLinkingListFilter,

    # Establishment Admin
    EstablishmentAdminLinkingCreate,
    EstablishmentAdminLinkingDetail,
    EstablishmentAdminLinkingListFilter,

    # EstablishmentGuard
    EstablishmentGuardLinkingCreate,
    EstablishmentGuardLinkingDetail,
    EstablishmentGuardLinkingListFilter,
)

urlpatterns = [
    # Authentication Flow
    path('generate-otp/', GenerateOTPLoginView.as_view(), name='generate-otp'),
    path('verify-otp/', VerifyOTPLoginView.as_view(), name='verify-otp'),
    path('custom-logout/', CustomLogoutView.as_view(), name='custom-logout'),

    # Create initial super admin user
    path('super-admin-user-setup/', SuperAdminUserSetup.as_view(), name='super-admin-user-setup'),

    # User management Flow
    path('', UserCreate.as_view(), name='user-create'),
    path('<int:pk>', UserDetails.as_view(), name='user-details'),
    path('list/', UserList.as_view(), name='user-list'),
    path('list-filter/', UserListFilter.as_view(), name='user-list-filter'),

    # Organization Administrator
    path('organization-administrator-linking/', OrganizationAdministratorLinkingCreate().as_view(), name='organization-administrator-linking'),
    path('organization-administrator-linking/<int:pk>', OrganizationAdministratorLinkingDetail.as_view(), name='organization-administrator-linking-detail'),
    path('organization-administrator-linking-list-filter/', OrganizationAdministratorLinkingListFilter.as_view(), name='organization-administrator-linking-list-filter'),

    # Establishment Admin
    path('establishment-admin-linking/', EstablishmentAdminLinkingCreate.as_view(), name='establishment-admin-linking'),
    path('establishment-admin-linking/<int:pk>', EstablishmentAdminLinkingDetail.as_view(), name='establishment-admin-linking-detail'),
    path('establishment-admin-linking-list-filter/', EstablishmentAdminLinkingListFilter.as_view(), name='establishment-admin-linking-list-filter'),

    # Establishment Guard
    path('establishment-guard-linking/', EstablishmentGuardLinkingCreate.as_view(), name='establishment-guard-linking'),
    path('establishment-guard-linking/<int:pk>', EstablishmentGuardLinkingDetail.as_view(), name='establishment-guard-linking-detail'),
    path('establishment-guard-linking-list-filter/', EstablishmentGuardLinkingListFilter.as_view(), name='establishment-guard-linking-list-filter'),
]
