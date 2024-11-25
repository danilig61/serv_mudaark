from django.contrib import admin
from .models import File


class FileAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'file', 'speakers', 'language', 'duration', 'created_at', 'status')
    list_filter = ('status', 'created_at')
    search_fields = ('name', 'user__username')
    readonly_fields = ('created_at',)


admin.site.register(File, FileAdmin)
