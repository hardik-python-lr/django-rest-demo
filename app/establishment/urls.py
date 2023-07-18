from django.urls import path
from app.establishment.views import (
    # Establishment views
    EstablishmentCreate,
    EstablishmentDetail,
    EstablishmentList,
    EstablishmentListFilter,

    # Establishment views for Establishment Admin
    EstablishmentAdminEstablishmentList,
    EstablishmentAdminEstablishmentListFilter
)


urlpatterns = [
    # Establishment views
    path('', EstablishmentCreate.as_view(), name='establishment-create'),
    path('<int:pk>', EstablishmentDetail.as_view(), name='establishment-detail'),
    path('list/', EstablishmentList.as_view(), name='establishment-list'),
    path('list-filter/', EstablishmentListFilter.as_view(), name='establishment-list-filter'),

    # Establishment views for Establishment Admin
    path('establishment-list-for-establishment-admin/', EstablishmentAdminEstablishmentList.as_view(), name='establishment-list-for-establishment-admin'),
    path('establishment-list-filter-for-establishment-admin/', EstablishmentAdminEstablishmentListFilter.as_view(), name='establishment-list-filter-for-establishment-admin'),
]
