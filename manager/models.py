from django.db import models
from django.contrib.auth.models import User   ##### import default user model from django (have encryption and security mesures like ... /////)

# Create your models here.

class Account(models.Model):
    """
    User accounts table schema
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    email = models.BinaryField()
    password = models.BinaryField()
    name = models.CharField(max_length=128)

    class Meta:
        unique_together = ('user', 'name')

    def __str__(self):
        return self.name