from django.urls import path
from app.building.views import (
    BuildingCreate,
    BuildingDetail,
    BuildingList,
    BuildingListFilter,
)


urlpatterns = [
    path('', BuildingCreate.as_view(), name='building-create'),
    path('<int:pk>', BuildingDetail.as_view(), name='building-detail'),
    path('list/', BuildingList.as_view(), name='building-list'),
    path('list-filter/', BuildingListFilter.as_view(), name='building-list-filter'),
]
