import base64
from io import BytesIO

from PIL import Image
from django.contrib.auth import authenticate
from django.core.files.uploadedfile import InMemoryUploadedFile
from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers

from .models import ExerciseAccess, Exercise, CustomUser, PlanExercise, TrainingPlan, Training, TrainingPlanAccess, \
    Group, Invitation

import logging

logger = logging.getLogger(__name__)


class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['first_name', 'last_name', 'email', 'password', 'role']
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def validate_email(self, value):
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use.")
        return value

    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        return value

    def create(self, validated_data):
        user = CustomUser(
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            email=validated_data['email'],
            username=validated_data['email'],
            role=validated_data['role'],
        )
        user.set_password(validated_data['password'])
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if email and password:
            user = authenticate(request=self.context.get('request'), username=email, password=password)

            if not user:
                raise serializers.ValidationError('No active account found with the given credentials')
        else:
            raise serializers.ValidationError('Must include "email" and "password".')

        data['user'] = user
        return data


class RoleUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['role']

    def validate(self, data):
        request = self.context.get('request')
        if request.user.role != 'user':
            raise serializers.ValidationError("Role can only be changed to 'trainer' from 'user'")
        if data.get('role') != 'trainer':
            raise serializers.ValidationError("Role can only be changed to 'trainer'")
        return data


class ExerciseSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = Exercise
        fields = ['id', 'name']


class ExerciseSerializer(serializers.ModelSerializer):
    image = serializers.SerializerMethodField()
    is_owner = serializers.SerializerMethodField()

    class Meta:
        model = Exercise
        fields = ['id', 'name', 'description', 'image', 'is_public', 'is_timed', 'is_owner']

    def validate_image(self, value):
        max_size = 10 * 1024 * 1024
        if value.size > max_size:
            raise serializers.ValidationError('Maksymalny rozmiar pliku to 10 MB.')
        return value

    def create(self, validated_data):
        image_data = validated_data.pop('image', None)
        if image_data:
            validated_data['image'] = self.compress_image(image_data)
        validated_data['is_public'] = False
        exercise = Exercise.objects.create(**validated_data)
        return exercise

    def compress_image(self, image):
        im = Image.open(image)
        im_io = BytesIO()
        im.save(im_io, format='JPEG', quality=70)
        im_io.seek(0)
        compressed_image = InMemoryUploadedFile(
            im_io, None, 'compressed_' + image.name, 'image/jpeg', im_io.tell(), None
        )
        return compressed_image

    @extend_schema_field(serializers.CharField())
    def get_image(self, obj):
        if obj.image:
            return base64.b64encode(obj.image).decode('utf-8')
        return None

    @extend_schema_field(serializers.BooleanField())
    def get_is_owner(self, obj):
        request = self.context.get('request')
        return obj.owner == request.user


class PlanExerciseCreateSerializer(serializers.ModelSerializer):
    exercise = serializers.PrimaryKeyRelatedField(queryset=Exercise.objects.all())

    class Meta:
        model = PlanExercise
        fields = ['exercise', 'repetitions', 'order']


class PlanExerciseReadSerializer(serializers.ModelSerializer):
    exercise = ExerciseSummarySerializer()
    is_timed = serializers.SerializerMethodField()

    class Meta:
        model = PlanExercise
        fields = ['exercise', 'repetitions', 'order', 'is_timed']

    @extend_schema_field(serializers.BooleanField())
    def get_is_timed(self, obj):
        return obj.exercise.is_timed


class TrainingPlanSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = TrainingPlan
        fields = ['id', 'name']


class TrainingPlanSerializer(serializers.ModelSerializer):
    exercises = PlanExerciseReadSerializer(many=True, source='planexercise_set')
    is_owner = serializers.SerializerMethodField()

    class Meta:
        model = TrainingPlan
        fields = ['id', 'name', 'description', 'exercises', 'is_owner']

    @extend_schema_field(serializers.BooleanField())
    def get_is_owner(self, obj):
        request = self.context.get('request')
        return obj.owner == request.user


class TrainingPlanCreateSerializer(serializers.ModelSerializer):
    exercises = PlanExerciseCreateSerializer(many=True)

    class Meta:
        model = TrainingPlan
        fields = ['id', 'name', 'description', 'exercises']

    def create(self, validated_data):
        user = self.context['request'].user
        exercises_data = validated_data.pop('exercises')
        training_plan = TrainingPlan.objects.create(owner=user, **validated_data)

        for index, exercise_data in enumerate(exercises_data):
            exercise = exercise_data['exercise']
            if exercise.owner != user and not ExerciseAccess.objects.filter(exercise=exercise, user=user).exists():
                raise serializers.ValidationError(f"User does not have access to exercise {exercise.id}")

            PlanExercise.objects.create(
                training_plan=training_plan,
                exercise=exercise,
                repetitions=exercise_data['repetitions'],
                order=exercise_data.get('order', index + 1)
            )
        return training_plan


class TrainingSerializer(serializers.ModelSerializer):
    training_plan = serializers.PrimaryKeyRelatedField(queryset=TrainingPlan.objects.all())
    group = serializers.PrimaryKeyRelatedField(queryset=Group.objects.all(), required=False, allow_null=True)
    is_trainer = serializers.SerializerMethodField()

    class Meta:
        model = Training
        fields = ['id', 'date', 'training_plan', 'group', 'is_trainer']

    def validate(self, data):
        user = self.context['request'].user
        training_plan = data['training_plan']

        if training_plan.owner != user and not TrainingPlanAccess.objects.filter(training_plan=training_plan, user=user).exists():
            raise serializers.ValidationError(f"User does not have access to training plan {training_plan.id}")

        return data

    def create(self, validated_data):
        validated_data['trainer'] = self.context['request'].user
        training = Training.objects.create(**validated_data)
        return training

    def get_is_trainer(self, obj):
        request = self.context.get('request', None)
        if request is None:
            return False
        return obj.trainer == request.user


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ['id', 'name', 'members', 'trainers']
        read_only_fields = ['id', 'members', 'trainers']


class InvitationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invitation
        fields = ['id', 'type', 'status', 'sender', 'recipient', 'group']
