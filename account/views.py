from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from account.serializers import UserRegistrationSerializer,UserLoginSerializer,UserProfileSerializer,UserChangePasswordSerializer,SendPasswordResetEmailSerializer,UserPasswordResetSerializer
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import MethodNotAllowed


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class UserRegistrationView(APIView):
  def post(self,request,format=None):
    serializer = UserRegistrationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()
    token = get_tokens_for_user(user)
    return Response({'token':token,'msg':'Registration Success'},status=status.HTTP_201_CREATED)


class UserLoginView(APIView):
  def post(self, request, format=None):
    serializer = UserLoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    email = serializer.data.get('email')
    password = serializer.data.get('password')
    user = authenticate(email=email, password=password)
    if user is not None:
      token = get_tokens_for_user(user)
      return Response({'token':token,'msg':'Login Success'}, status=status.HTTP_200_OK)
    else:
      return Response({'errors':{'non_field_errors':['Email or Password is not Valid']}}, status=status.HTTP_404_NOT_FOUND)
    

class UserProfileView(APIView):
  permission_classes = [IsAuthenticated]
  def get(self, request, format=None):
    serializer = UserProfileSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)
  


class UserChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = UserChangePasswordSerializer(data=request.data, context={'user': request.user})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'msg': 'Password changed successfully'}, status=status.HTTP_200_OK)

    def get(self, request, format=None):
        raise MethodNotAllowed('GET')


  
class SendPasswordResetEmailView(APIView):
  def post(self, request, format=None):
    serializer = SendPasswordResetEmailSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)

class UserPasswordResetView(APIView):
  def post(self, request, uid, token, format=None):
    serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)





from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from .models import TreadmillData
from .serializers import FitnessMetricsSerializer

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def save_treadmill_metrics(request):
    user_id = request.data.get('user_id')
    distance = request.data.get('distance')
    duration = request.data.get('duration')
    speed = request.data.get('speed')
    heart_rate = request.data.get('heart_rate')
    calories_burned = request.data.get('calories_burned')

    # Validate input data
    if user_id is None or distance is None or duration is None or speed is None or heart_rate is None or calories_burned is None:
        return Response({'error': 'All fields are required'}, status=400)

    # Create TreadmillData object and save to database
    treadmill_data = TreadmillData.objects.create(
        user_id=user_id,
        distance=distance,
        duration=duration,
        speed=speed,
        heart_rate=heart_rate,
        calories_burned=calories_burned
    )
    serializer = FitnessMetricsSerializer(treadmill_data)
    return Response(serializer.data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_workout_history(request):
    workouts = TreadmillData.objects.all()
    serializer = FitnessMetricsSerializer(workouts, many=True)
    return Response(serializer.data)
