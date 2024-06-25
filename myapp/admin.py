from django.contrib import admin
from .models import Invitation, Exercise, TrainingPlan, PlanExercise, Group, Training, CustomUser

admin.site.register(CustomUser)
admin.site.register(Invitation)
admin.site.register(Exercise)
admin.site.register(TrainingPlan)
admin.site.register(PlanExercise)
admin.site.register(Group)
admin.site.register(Training)