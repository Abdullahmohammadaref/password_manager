"""
##### file was made to create url patterns for manager app
"""

from django.urls import path   ##### imported urls from main password_manager project urls.py file

from . import views  ##### imported all functions from views.py

"""
#####
adding url paths for views.py functions (calling these urls for example <domain name/localhost>/new_account))
will run the related function in views.py
"""

urlpatterns = [
    path("", views.home, name="home"),
    path("login", views.log_in, name="login"),
    path("logout", views.log_out, name="logout"),
    path("register", views.register, name="register"),
    path('activate/<uidb64>/<token>', views.activate_account, name='activate'),
    path('authenticate/<uidb64>/<token>', views.authenticate_user, name='authenticate'),
    path('reset/<uidb64>/<token>', views.password_reset, name='reset'),
    path("new_account", views.new_account, name="new_account"),
    path("<int:account_id>", views.account, name="account"),
    path("forgot_password", views.forgot_password, name="forgot_password"),
    path("new_password/<int:user_id>", views.new_password, name="new_password"),
    path("remove/<int:account_id>", views.remove_account, name="remove"),
]
