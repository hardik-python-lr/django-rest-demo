from django.urls import path
from app.flat.views import (
    FlatCreate,
    FlatDetail,
    FlatList,
    FlatListFilter,
)


urlpatterns = [
    path('', FlatCreate.as_view(), name='flat-create'),
    path('<int:pk>', FlatDetail.as_view(), name='flat-detail'),
    path('list/', FlatList.as_view(), name='flat-list'),
    path('list-filter/', FlatListFilter.as_view(), name='flat-list-filter'),
]
