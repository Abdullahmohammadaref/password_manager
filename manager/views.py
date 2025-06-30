import string
from django.conf import settings
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.db import IntegrityError

from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import EmailMessage


from .models import *
import secrets
from cryptography.fernet import Fernet

from .tokens import account_activation_token


##### Fetch the encryption/decryption key form settings.py
fernet = Fernet(settings.KEY)

# Create your views here.

def generate_strong_password():
    """
    This function is responsible for generating a strong password.
    This password can then be suggested to the user when needed
    """
    suggested_password = []
    password_length = 16
    for i in range(password_length - 3):
        """
        have a random mix of 13 characters from ascii letters, digits and special characters
        """
        suggested_password.append(secrets.choice(
            string.ascii_letters +
            string.digits +
            string.punctuation
        ))
    """
    Last 3 characters are added sperately one by one from asci-letters, then digits then special characters 
    This is done incase the precious 13 characters didnt have either ascii_letters or digits or special characters due to randomness
    """
    suggested_password.append(secrets.choice(string.ascii_letters))
    suggested_password.append(secrets.choice(string.digits))
    suggested_password.append(secrets.choice(string.punctuation))
    secrets.SystemRandom().shuffle(suggested_password)
    suggested_password = "".join(suggested_password)
    return suggested_password

def activate_account(request, uidb64, token):
    """
    #####
    When user clicks the activation link sent by email:
        1- encoded user id is decoded and used to get the user object
        2- check if the token is valid
        3- change account is_active attribute to True and save those changes
        4- load the login page with a sucess message
    """
    User = get_user_model()

    uid = force_str(urlsafe_base64_decode(uidb64))
    user = User.objects.get(pk=uid)

    if account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        return render(request, "manager/login.html", {
            "message": "account created successfully, you can login now",
        })
    else:
        return render(request, "manager/login.html", {
            "message": "expired link, user account not activated,",
        })

def authenticate_user(request, uidb64, token):
    """
    #####
    When user clicks the authentication link sent by email:
        1- encoded user id is decoded and used to get the user object
        2- check if the token is valid
        3- login the user and load the login page with a success message
    """
    User = get_user_model()

    uid = force_str(urlsafe_base64_decode(uidb64))
    user = User.objects.get(pk=uid)

    if account_activation_token.check_token(user, token):
        login(request, user)
        return redirect('home')
    else:
        return render(request, "manager/login.html", {
            "message": "expired link, login failed,",
        })

def password_reset(request, uidb64, token):
    """
    #####
    When user clicks the activation link sent by email:
        1- encoded user id is decoded and used to get the user object
        2- check if the token is valid
        3- load a page where the user can input his new password
    """
    suggested_password = generate_strong_password()

    User = get_user_model()

    uid = force_str(urlsafe_base64_decode(uidb64))
    user = User.objects.get(pk=uid)

    if account_activation_token.check_token(user, token):
        id = force_str(urlsafe_base64_decode(uidb64))
        return render(request, "manager/new_password.html", {
            "user_id": id,
            "suggested_password": suggested_password,
        })
    else:
        return render(request, "manager/login.html", {
            "message": "expired link, account password cannot be reset,",
        })

def new_password(request, user_id):
    """
    #####
    after receiving a reset password link on email and the link is clicked, this function is called
    It loads a html page that allows the user to input his new password securely
    This password it then hashed and salted. and the old password hash is replaced with the new password hash
    """
    suggested_password = generate_strong_password()
    if request.method == "POST":
        password = request.POST['password']
        confirmed_password = request.POST['confirmed_password']
        ##### get the id of the user that will change his password
        id = user_id

        """
        #####
        perform some checks to approve password strength
        """
        if password != confirmed_password:
            return render(request, "manager/new_password.html", {
                "message": "Passwords do not match.",
                "user_id": id,
                "suggested_password": suggested_password,
            })
        if len(password) < 8:
            return render(request, "manager/new_password.html", {
                "message": "Password must be at least 8 characters.",
                "user_id": id,
                "suggested_password": suggested_password,
            })

        letter_exists = False
        number_exists = False
        special_character_exists = False

        if password:
            for i in password:
                if i in string.ascii_letters:
                    letter_exists = True
                elif i in string.digits:
                    number_exists = True
                elif i in string.punctuation:
                    special_character_exists = True

            if not letter_exists:
                return render(request, "manager/new_password.html", {
                    "message": "Password should contain at least one letter",
                    "user_id": id,
                    "suggested_password": suggested_password,
                })

            if not number_exists:
                return render(request, "manager/new_password.html", {
                    "message": "Password should contain at least one number",
                    "user_id": id,
                    "suggested_password": suggested_password,
                })

            if not special_character_exists:
                return render(request, "manager/new_password.html", {
                    "message": "Password should contain at least one special character",
                    "user_id": id,
                    "suggested_password": suggested_password,
                })

        else:
            return render(request, "manager/new_password.html", {
                "message": "Password must not be empty",
                "user_id": id,
                "suggested_password": suggested_password,
            })

        """
        #####
        If all checks are passed then change the password and redirect to login page
        """
        user = User.objects.get(pk=id)
        user.set_password(password)
        user.save()
        return render(request, "manager/login.html", {
            "message": "Password successfully changed.",
        })
    else:
        return render(request, "manager/new_password.html", {
            "user_id": user_id,
            "suggested_password": suggested_password,
        })

def home(request):
    '''
    #####
    If user is logged in, and then allow access to the home page and load all the user account names
    '''
    if request.user.is_authenticated:
        accounts = Account.objects.filter(user=request.user)
        return render(request,'manager/home.html',{
            "accounts": accounts,
        })
    else:
        return redirect('login')

def log_out(request):
    """
    #####
    If user is logged in and the logout url is called then logout the user and load the login page
    """
    if request.user.is_authenticated:
        logout(request)
        return HttpResponseRedirect(reverse("home"))
    else:
        return redirect('login')

def new_account(request):
    """
    #####
    Loads the page where user can add a new account to the password manager.
    When he submits the form the email and passwords are encrypted
    (not hashed and salted because we want to retrieve the information by decryption if user request those information)
    Then the data is saved in the database and user is redirected to the home page
    """
    if request.user.is_authenticated:
        suggested_password = generate_strong_password()
        if request.method == "POST":
            email = request.POST['email'].lower()
            password = request.POST['password']
            name = request.POST['name'].lower()
            encrypted_email = fernet.encrypt(email.encode())
            encrypted_password = fernet.encrypt(password.encode())

            current_user = request.user

            account = Account(
                email=encrypted_email,
                name=name,
                password=encrypted_password,
                user=current_user,
            )

            account.save()
            return redirect("home")
        else:
            return render(request, 'manager/new_account.html', {
                "suggested_password": suggested_password
            })
    else:
        return redirect('login')

def account(request, account_id):
    """
    #####
    This function loads a special page for a user account when he requests to see his credentials
    Email and password are decrypted and shown to the user
    """
    if request.user.is_authenticated:
        account = Account.objects.get(pk=account_id)

        decrypted_password = fernet.decrypt(account.password).decode()
        decrypted_email = fernet.decrypt(account.email).decode()

        return render(request, 'manager/account.html', {
            "password": decrypted_password,
            "email": decrypted_email,
        })
    else:
        return redirect('login')

def remove_account(request, account_id):
    if request.user.is_authenticated:
        account = Account.objects.get(pk=account_id)
        account.delete()
        return redirect("home")
    else:
        return redirect('login')

def forgot_password(request):
    """
    #####
    If user forgets his password and the forgot_password url is called then a page where user enter his email and username will be laoded
    after submitting the function checks if there is a user with the same username and email (if yes then continue)
    in the end it sends a password reset link through email
    """
    if request.method == "POST":

        username = request.POST['username'].lower()
        email = request.POST["email"].lower()

        user = User.objects.filter(username=username, email=email, is_active=True).first()
        if user:
            subject = "Password Reset"
            url = render_to_string('manager/password_reset_email.html', {
                ##### get the current domain
                'domain': get_current_site(request).domain,
                ##### get the user id and encode it, then convert the byte code to base64 encoding for transmitting the binary data
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                ##### generate a special user token
                'token': account_activation_token.make_token(user),
                ##### input the protocol used
                "protocol": "http",
            })
            ##### construct and email
            email = EmailMessage(subject, url, to=[email])
            if email.send():
                return render(request, "manager/login.html", {
                    "message": "email sent sucessfully",
                })
            else:
                return render(request, "manager/login.html", {
                    "message": "email was not sent ",
                })

        else:
            return render(request, "manager/forgot_password.html", {
                "message": "Invalid credentials."
            })
    else:
        return render(request, "manager/forgot_password.html")

def log_in(request):
    """
    #####
    If login url is called then a page where user can enter is account information is called
    after submitting, the function checks if there is a user with the same username and email (if yes then continue)
    in the end it sends a user authentication link through email
    """
    if request.method == "POST":

        username = request.POST['username'].lower()
        email = request.POST["email"].lower()

        user = User.objects.filter(username=username, email=email, is_active=True).first()

        if user:
            subject = "User Authentication"
            url = render_to_string('manager/authentication_email.html', {
                'domain': get_current_site(request).domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': account_activation_token.make_token(user),
                "protocol": "http",
            })
            email = EmailMessage(subject, url, to=[email])
            if email.send():
                return render(request, "manager/login.html", {
                    "message": "email sent sucessfully",
                })
            else:
                return render(request, "manager/login.html", {
                    "message": "email was not sent ",
                })

        else:
            return render(request, "manager/login.html", {
                "message": "Invalid credentials."
            })
    else:
        return render(request, "manager/login.html")

def register(request):
    """
    #####
    If a new user want to register and the register url is called then a page where user enter his new account information is loaded
    after submitting the function checks if there is a user with the same username and email (if yes then revoke user request)
    in the end it sends an account activation link through email
    """
    suggested_password = generate_strong_password()
    if request.method == "POST":
        username = request.POST["username"].lower()
        email = request.POST['email'].lower()
        password = request.POST['password']
        confirmed_password = request.POST['confirmed_password']
        if password != confirmed_password:
            return render(request, "manager/register.html", {
                "message": "Passwords do not match."
            })

        if len(password) < 8:
            return render(request, "manager/register.html", {
                "message": "Password must be at least 8 characters."
            })

        letter_exists = False
        number_exists = False
        special_character_exists = False

        if password:
            for i in password:
                if i in string.ascii_letters:
                    letter_exists = True
                elif i in string.digits:
                    number_exists = True
                elif i in string.punctuation:
                    special_character_exists = True

            if not letter_exists:
                return render(request, "manager/register.html", {
                    "message": "Password should contain at least one letter"
                })

            if not number_exists:
                return render(request, "manager/register.html", {
                    "message": "Password should contain at least one number"
                })

            if not special_character_exists:
                return render(request, "manager/register.html", {
                    "message": "Password should contain at least one special character"
                })
        else:
            return render(request, "manager/register.html", {
                "message": "Password must not be empty"
            })

        try:

            user_username_exists = User.objects.filter(username=username,is_active=False)
            user_email_exists = User.objects.filter(email=email,is_active=False)

            if user_username_exists.exists():
                user_username_exists.delete()

            if user_email_exists.exists():
                user_email_exists.delete()



            user = User.objects.create_user(username=username, email=email, password=password, is_active=False)
            user.save()
        except IntegrityError:
            return render(request, "manager/register.html", {
                "message": "Email or Username already exists.",
                "suggested_password": suggested_password
            })

        subject = "Account activation"
        url = render_to_string('manager/activation_email.html', {
            'domain': get_current_site(request).domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': account_activation_token.make_token(user),
            "protocol": "http",
        })
        email = EmailMessage(subject, url, to=[email])
        if email.send():
            return render(request, "manager/register.html", {
                "message": "email sent successfully",
                "suggested_password": suggested_password
            })
        else:
            return render(request, "manager/register.html", {
                "message": "email was not sent ",
                "suggested_password": suggested_password
            })
    else:
        return render(request, 'manager/register.html',{
                    "suggested_password": suggested_password,
                })

        #login(request, user)
        #return HttpResponseRedirect(reverse("home"))

