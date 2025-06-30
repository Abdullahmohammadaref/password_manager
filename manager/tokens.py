"""
#####
Reference to: Django_tutorials/15_Django-email-confirm at main · pythonlessons/Django_tutorials, 2022
https://github.com/pythonlessons/Django_tutorials/blob/main/15_Django-email-confirm/users/tokens.py
"""
from django.contrib.auth.tokens import PasswordResetTokenGenerator

class AccountActivationTokenGenerator(PasswordResetTokenGenerator):
    """
    #####
    This class is responsible for generating a special user token that are available for 2 minutes only
    after setting the inputs, the django PasswordResetTokenGenerator is called to create a token with these inputs
    """
    def _make_hash_value(self, user, timestamp):
        return (
            ##### user object is included to make this token user specific
            ##### timestamp of token creation is added so that it can be used to know if more than two minutes have passed after creation
            ##### user active status is added to make this token invalid if the user status changes
            str(user) +
            str(timestamp) +
            str(user.is_active)
        )

account_activation_token = AccountActivationTokenGenerator()