from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated, BasePermission
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes, parser_classes
from rest_framework_simplejwt.tokens import RefreshToken

from .models import Exercise, ExerciseAccess, TrainingPlan, TrainingPlanAccess, Training, CustomUser, Group, Invitation
from .serializers import UserRegistrationSerializer, LoginSerializer, ExerciseSerializer, TrainingPlanSerializer, \
    TrainingSerializer, ExerciseSummarySerializer, TrainingPlanSummarySerializer, TrainingPlanCreateSerializer, \
    RoleUpdateSerializer, GroupSerializer, InvitationSerializer

import logging

logger = logging.getLogger(__name__)


@extend_schema(
    request=UserRegistrationSerializer,
    responses={201: UserRegistrationSerializer}
)
@api_view(['POST'])
def register_user(request):
    if request.method == 'POST':
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    request=LoginSerializer,
    responses={200: 'application/json'}
)
@api_view(['POST'])
def login_user(request):
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.validated_data['user']
        refresh = RefreshToken.for_user(user)
        logger.info(f"Generated tokens for user ID: {user.id}")
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'role': user.role,
        }, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def update_role_to_trainer(request):
    try:
        user = request.user
        serializer = RoleUpdateSerializer(user, data=request.data, partial=True, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except CustomUser.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


class IsOwner(BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.owner == request.user


@extend_schema(
    responses={200: ExerciseSummarySerializer(many=True)}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_exercises(request):
    user = request.user
    owned_exercises = Exercise.objects.filter(owner=user)
    accessed_exercises = Exercise.objects.filter(accesses__user=user)
    exercises = owned_exercises | accessed_exercises
    serializer = ExerciseSummarySerializer(exercises, many=True)
    return Response(serializer.data)


@extend_schema(
    responses={200: ExerciseSerializer}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_exercise_detail(request, pk):
    try:
        exercise = Exercise.objects.get(pk=pk)
        if exercise.owner != request.user and not ExerciseAccess.objects.filter(exercise=exercise, user=request.user).exists():
            return Response({'error': 'You do not have permission to view this exercise.'}, status=status.HTTP_403_FORBIDDEN)
        serializer = ExerciseSerializer(exercise, context={'request': request})
        return Response(serializer.data)
    except Exercise.DoesNotExist:
        return Response({'error': 'Exercise not found.'}, status=status.HTTP_404_NOT_FOUND)


@extend_schema(
    request=ExerciseSerializer,
    responses={201: None}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def create_exercise(request):
    logger.info(f"Request data: {request.data}")

    serializer = ExerciseSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        serializer.save(owner=request.user)
        logger.info("Exercise created successfully")
        return Response(status=status.HTTP_201_CREATED)
    else:
        logger.error(f"Validation errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    request=ExerciseSerializer,
    responses={200: None}
)
@api_view(['PUT'])
@permission_classes([IsAuthenticated, IsOwner])
def update_exercise(request, pk):
    try:
        exercise = Exercise.objects.get(pk=pk, owner=request.user)
    except Exercise.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    serializer = ExerciseSerializer(exercise, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    request=None,
    responses={204: None}
)
@api_view(['DELETE'])
@permission_classes([IsAuthenticated, IsOwner])
def delete_exercise(request, pk):
    try:
        exercise = Exercise.objects.get(pk=pk, owner=request.user)
    except Exercise.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    exercise.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema(
    responses={200: TrainingPlanSummarySerializer(many=True)}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_training_plans(request):
    user = request.user
    owned_plans = TrainingPlan.objects.filter(owner=user)
    accessed_plans = TrainingPlan.objects.filter(accesses__user=user)
    plans = owned_plans | accessed_plans
    serializer = TrainingPlanSummarySerializer(plans, many=True)
    return Response(serializer.data)


@extend_schema(
    responses={200: TrainingPlanSerializer}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_training_plan_detail(request, pk):
    try:
        training_plan = TrainingPlan.objects.get(pk=pk)
        if training_plan.owner != request.user and not TrainingPlanAccess.objects.filter(training_plan=training_plan, user=request.user).exists():
            return Response({'error': 'You do not have permission to view this training plan.'}, status=status.HTTP_403_FORBIDDEN)
        serializer = TrainingPlanSerializer(training_plan, context={'request': request})
        return Response(serializer.data)
    except TrainingPlan.DoesNotExist:
        return Response({'error': 'Training plan not found.'}, status=status.HTTP_404_NOT_FOUND)


@extend_schema(
    request=TrainingPlanCreateSerializer,
    responses={201: None}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_training_plan(request):
    logger.debug(f"Request data: {request.data}")
    serializer = TrainingPlanCreateSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        serializer.save()
        return Response(status=status.HTTP_201_CREATED)
    else:
        logger.debug(f"Serializer errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    request=TrainingPlanSerializer,
    responses={200: None}
)
@api_view(['PUT'])
@permission_classes([IsAuthenticated, IsOwner])
def update_training_plan(request, pk):
    try:
        training_plan = TrainingPlan.objects.get(pk=pk, owner=request.user)
    except TrainingPlan.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    serializer = TrainingPlanSerializer(training_plan, data=request.data, partial=True, context={'request': request})
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    request=None,
    responses={204: None}
)
@api_view(['DELETE'])
@permission_classes([IsAuthenticated, IsOwner])
def delete_training_plan(request, pk):
    try:
        training_plan = TrainingPlan.objects.get(pk=pk, owner=request.user)
    except TrainingPlan.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    training_plan.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema(
    responses={200: TrainingSerializer(many=True)}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_trainings(request):
    user = request.user
    trainings = Training.objects.filter(trainer=user)
    serializer = TrainingSerializer(trainings, many=True, context={'request': request})
    return Response(serializer.data)


@extend_schema(
    responses={200: TrainingSerializer}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_training_detail(request, pk):
    try:
        training = Training.objects.get(pk=pk)
        if training.trainer != request.user:
            return Response({'error': 'You do not have permission to view this training.'}, status=status.HTTP_403_FORBIDDEN)
        serializer = TrainingSerializer(training, context={'request': request})
        return Response(serializer.data)
    except Training.DoesNotExist:
        return Response({'error': 'Training not found.'}, status=status.HTTP_404_NOT_FOUND)


@extend_schema(
    request=TrainingSerializer,
    responses={201: TrainingSerializer}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_training(request):
    logger.debug(f"Request data: {request.data}")
    serializer = TrainingSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        logger.debug(f"Serializer valid data: {serializer.validated_data}")
        training = serializer.save()
        return Response(TrainingSerializer(training).data, status=status.HTTP_201_CREATED)
    else:
        logger.debug(f"Serializer errors: {serializer.errors}")
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    request=TrainingSerializer,
    responses={200: TrainingSerializer}
)
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_training(request, pk):
    try:
        training = Training.objects.get(pk=pk, trainer=request.user)
    except Training.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    serializer = TrainingSerializer(training, data=request.data, partial=True, context={'request': request})
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    request=None,
    responses={204: None}
)
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_training(request, pk):
    try:
        training = Training.objects.get(pk=pk, trainer=request.user)
    except Training.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    training.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema(
    request=GroupSerializer,
    responses={201: GroupSerializer}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_group(request):
    user = request.user
    if user.role not in ['trainer', 'fitness_club']:
        return Response({'error': 'You do not have permission to create a group.'}, status=status.HTTP_403_FORBIDDEN)

    serializer = GroupSerializer(data=request.data)
    if serializer.is_valid():
        group = serializer.save(owner=user)
        group.trainers.add(user)
        return Response(GroupSerializer(group).data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    request=GroupSerializer,
    responses={200: GroupSerializer}
)
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_group(request, pk):
    user = request.user
    try:
        group = Group.objects.get(pk=pk)
    except Group.DoesNotExist:
        return Response({'error': 'Group not found.'}, status=status.HTTP_404_NOT_FOUND)

    if user != group.owner:
        return Response({'error': 'You do not have permission to edit this group.'}, status=status.HTTP_403_FORBIDDEN)

    serializer = GroupSerializer(group, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    responses={204: None}
)
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_group(request, pk):
    user = request.user
    try:
        group = Group.objects.get(pk=pk)
    except Group.DoesNotExist:
        return Response({'error': 'Group not found.'}, status=status.HTTP_404_NOT_FOUND)

    if user != group.owner:
        return Response({'error': 'You do not have permission to delete this group.'}, status=status.HTTP_403_FORBIDDEN)

    group.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema(
    request=InvitationSerializer,
    responses={201: InvitationSerializer}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_invitation(request):
    user = request.user
    data = request.data
    try:
        group = Group.objects.get(id=data['group'])
    except Group.DoesNotExist:
        return Response({'error': 'Group not found.'}, status=status.HTTP_404_NOT_FOUND)

    if data['type'] == 'group_member' and (user not in group.trainers.all() and user != group.owner):
        return Response({'error': 'You do not have permission to send this invitation.'}, status=status.HTTP_403_FORBIDDEN)

    if data['type'] == 'group_trainer' and user != group.owner:
        return Response({'error': 'You do not have permission to send this invitation.'}, status=status.HTTP_403_FORBIDDEN)

    recipient = CustomUser.objects.get(id=data['recipient'])
    if recipient.role not in ['user', 'trainer']:
        return Response({'error': 'Recipient must have role user or trainer.'}, status=status.HTTP_400_BAD_REQUEST)

    invitation = Invitation.objects.create(
        type=data['type'],
        sender=user,
        recipient=recipient,
        group=group,
        status='waiting'
    )
    return Response(InvitationSerializer(invitation).data, status=status.HTTP_201_CREATED)


@extend_schema(
    responses={200: InvitationSerializer(many=True)}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_invitations(request):
    user = request.user
    sent_invitations = Invitation.objects.filter(sender=user, status='waiting')
    received_invitations = Invitation.objects.filter(recipient=user, status='waiting')
    data = {
        'sent': InvitationSerializer(sent_invitations, many=True).data,
        'received': InvitationSerializer(received_invitations, many=True).data,
    }
    return Response(data, status=status.HTTP_200_OK)


@extend_schema(
    responses={204: None}
)
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_invitation(request, pk):
    user = request.user
    try:
        invitation = Invitation.objects.get(id=pk)
    except Invitation.DoesNotExist:
        return Response({'error': 'Invitation not found.'}, status=status.HTTP_404_NOT_FOUND)

    if invitation.status != 'waiting':
        return Response({'error': 'You can only delete invitations with status waiting.'}, status=status.HTTP_400_BAD_REQUEST)

    if invitation.sender != user and invitation.recipient != user:
        return Response({'error': 'You do not have permission to delete this invitation.'}, status=status.HTTP_403_FORBIDDEN)

    invitation.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)
