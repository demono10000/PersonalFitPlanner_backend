from django.conf.urls.static import static
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from django.conf import settings

from .views import register_user, login_user, create_exercise, update_exercise, delete_exercise, create_training_plan, \
    create_training, get_user_exercises, get_exercise_detail, get_user_training_plans, get_training_plan_detail, \
    update_training_plan, delete_training_plan, get_training_detail, update_training, delete_training, \
    get_user_trainings, update_role_to_trainer, update_group, delete_group, create_group, send_invitation, \
    list_invitations, delete_invitation

urlpatterns = [
    path('register/', register_user, name='register_user'),
    path('login/', login_user, name='login_user'),
    path('update-role-to-trainer/', update_role_to_trainer, name='update_role_to_trainer'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('exercises/', get_user_exercises, name='get_user_exercises'),
    path('exercises/<int:pk>/', get_exercise_detail, name='get_exercise_detail'),
    path('exercises/create/', create_exercise, name='create_exercise'),
    path('exercises/<int:pk>/update/', update_exercise, name='update_exercise'),
    path('exercises/<int:pk>/delete/', delete_exercise, name='delete_exercise'),
    path('training_plans/', get_user_training_plans, name='get_user_training_plans'),
    path('training_plans/<int:pk>/', get_training_plan_detail, name='get_training_plan_detail'),
    path('training_plans/<int:pk>/update/', update_training_plan, name='update_training_plan'),
    path('training_plans/<int:pk>/delete/', delete_training_plan, name='delete_training_plan'),
    path('training_plans/create/', create_training_plan, name='create_training_plan'),
    path('trainings/', create_training, name='create_training'),
    path('trainings/<int:pk>/', get_training_detail, name='get_training_detail'),
    path('trainings/<int:pk>/update/', update_training, name='update_training'),
    path('trainings/<int:pk>/delete/', delete_training, name='delete_training'),
    path('trainings/list/', get_user_trainings, name='get_user_trainings'),
    path('groups/create/', create_group, name='create_group'),
    path('groups/<int:pk>/update/', update_group, name='update_group'),
    path('groups/<int:pk>/delete/', delete_group, name='delete_group'),
    path('invitations/send/', send_invitation, name='send_invitation'),
    path('invitations/list/', list_invitations, name='list_invitations'),
    path('invitations/<int:pk>/delete/', delete_invitation, name='delete_invitation'),
]