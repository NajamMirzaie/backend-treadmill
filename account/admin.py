from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from account.models import User


class UserModelAdmin(BaseUserAdmin):

    # The fields to be used in displaying the User model.
    # These override the definitions on the base UserAdmin
    # that reference specific fields on auth.User.
    list_display = ["id","email", "name", "profile_image", "is_admin"]
    list_filter = ["is_admin"]
    fieldsets = [
        ("User Credentials", {"fields": ["email", "password"]}),
        ("Personal info", {"fields": ["name","profile_image"]}),
        ("Permissions", {"fields": ["is_admin"]}),
    ]
    # add_fieldsets is not a standard ModelAdmin attribute. UserAdmin
    # overrides get_fieldsets to use this attribute when creating a user.
    add_fieldsets = [
        (
            None,
            {
                "classes": ["wide"],
                "fields": ["email", "name","profile_image", "password1", "password2"],
            },
        ),
    ]
    search_fields = ["email"]
    ordering = ["email","id"]
    filter_horizontal = []


# Now register the new UserAdmin...
admin.site.register(User, UserModelAdmin)


from .models import TreadmillData

@admin.register(TreadmillData)
class TreadmillDataAdmin(admin.ModelAdmin):
    list_display = ['user', 'timestamp', 'distance', 'duration', 'speed', 'heart_rate', 'calories_burned']
    search_fields = ['user__username', 'timestamp']
    list_filter = ['user', 'timestamp']
    readonly_fields = ['timestamp']

