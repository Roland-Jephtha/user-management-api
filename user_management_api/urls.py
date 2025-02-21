
from django.contrib import admin
from django.urls import path, include


from django.conf import settings
from django.conf.urls.static import static

from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi




schema_view = get_schema_view(
    openapi.Info(
        title="User Management API",
        default_version='v1',
        description="Get all data on  User Management API",
        terms_of_service="",
        contact=openapi.Contact(email=""),
        license=openapi.License(name="User Management API License"),
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
)





urlpatterns = [
    path('', schema_view.with_ui('swagger', cache_timeout=0),
         name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc',
         cache_timeout=0), name='schema-redoc'),
    path('admin/', admin.site.urls),
    path('user-management/', include("management.urls")),

   
]



if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
