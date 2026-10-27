from django.contrib.auth.models import User
from django.db import models

class Comment(models.Model):
    author = models.CharField(max_length=100)
    text = models.TextField()


class Note(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    text = models.TextField()
