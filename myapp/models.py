from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import AbstractUser
from django.db import models
import uuid


class CustomUser(AbstractUser):
    ROLE_CHOICES = [
        ('user', 'User'),
        ('trainer', 'Trainer'),
        ('fitness_club', 'Fitness Club'),
    ]

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='user')

    def __str__(self):
        return f"{self.first_name} {self.last_name}"


class Invitation(models.Model):
    STATUS_CHOICES = [
        ('waiting', 'Waiting'),
        ('accepted', 'Accepted'),
        ('denied', 'Denied'),
    ]

    TYPE_CHOICES = [
        ('group_member', 'Group Member'),
        ('group_trainer', 'Group Trainer'),
    ]

    id = models.AutoField(primary_key=True)
    type = models.CharField(max_length=100, choices=TYPE_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='waiting')
    sender = models.ForeignKey(CustomUser, related_name='sent_invitations', on_delete=models.CASCADE)
    recipient = models.ForeignKey(CustomUser, related_name='received_invitations', on_delete=models.CASCADE)
    group = models.ForeignKey('Group', related_name='invitations', null=True, blank=True, on_delete=models.CASCADE)

    def __str__(self):
        return f"Invitation from {self.sender} to {self.recipient} for group {self.group}"


class Exercise(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    image = models.BinaryField(blank=True, null=True)
    is_public = models.BooleanField(default=False)
    is_timed = models.BooleanField(default=False)
    owner = models.ForeignKey(CustomUser, related_name='exercises', on_delete=models.CASCADE)

    def __str__(self):
        return self.name


class ExerciseAccess(models.Model):
    exercise = models.ForeignKey(Exercise, related_name='accesses', on_delete=models.CASCADE)
    user = models.ForeignKey(CustomUser, related_name='exercise_accesses', on_delete=models.CASCADE)
    granted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('exercise', 'user')

    def __str__(self):
        return f"{self.user} has access to {self.exercise}"


class TrainingPlan(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    exercises = models.ManyToManyField('Exercise', through='PlanExercise', related_name='training_plans')
    owner = models.ForeignKey(CustomUser, related_name='owned_training_plans', on_delete=models.CASCADE)

    def __str__(self):
        return self.name


class TrainingPlanAccess(models.Model):
    training_plan = models.ForeignKey(TrainingPlan, related_name='accesses', on_delete=models.CASCADE)
    user = models.ForeignKey(CustomUser, related_name='training_plan_accesses', on_delete=models.CASCADE)
    granted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('training_plan', 'user')

    def __str__(self):
        return f"{self.user} has access to {self.training_plan}"


class PlanExercise(models.Model):
    training_plan = models.ForeignKey(TrainingPlan, on_delete=models.CASCADE)
    exercise = models.ForeignKey(Exercise, on_delete=models.CASCADE)
    repetitions = models.IntegerField()
    order = models.IntegerField()

    class Meta:
        ordering = ['order']

    def __str__(self):
        return f"{self.repetitions} reps of {self.exercise} in {self.training_plan}"


class Group(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    members = models.ManyToManyField(CustomUser, related_name='member_groups', blank=True)
    trainers = models.ManyToManyField(CustomUser, related_name='trained_groups', blank=True)
    owner = models.ForeignKey(CustomUser, related_name='owned_groups', on_delete=models.CASCADE)

    def __str__(self):
        return self.name


class Training(models.Model):
    id = models.AutoField(primary_key=True)
    date = models.DateTimeField()
    training_plan = models.ForeignKey(TrainingPlan, on_delete=models.CASCADE)
    trainer = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    group = models.ForeignKey(Group, on_delete=models.CASCADE, blank=True, null=True)

    def __str__(self):
        return f"Training on {self.date} by {self.trainer}"
