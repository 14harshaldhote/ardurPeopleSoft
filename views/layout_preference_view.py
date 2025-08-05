from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status

from trueAlign.models import LayoutPreference

class LayoutPreferenceView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            layout_preference = LayoutPreference.objects.get(user=request.user)
            return Response(layout_preference.layout, status=status.HTTP_200_OK)
        except LayoutPreference.DoesNotExist:
            return Response({}, status=status.HTTP_200_OK)

    def post(self, request):
        try:
            layout, created = LayoutPreference.objects.get_or_create(user=request.user)
            layout.layout = request.data
            layout.save()
            return Response(layout.layout, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
