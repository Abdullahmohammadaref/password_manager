from django.contrib import admin
from .models import *   ##### imported all created modules in models.py (database tables)

# Register your models here.

admin.site.register(Account)    ##### register these table to be viewable in admin interface