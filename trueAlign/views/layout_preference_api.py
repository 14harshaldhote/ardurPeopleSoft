from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.http import JsonResponse
import json

from trueAlign.models import LayoutPreference


class LayoutPreferenceAPIView(APIView):
    """
    API endpoint for managing user dashboard layout preferences
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Retrieve the current user's layout preferences
        """
        try:
            layout_preference = LayoutPreference.objects.get(user=request.user)
            return Response(layout_preference.layout, status=status.HTTP_200_OK)
        except LayoutPreference.DoesNotExist:
            # Return empty layout if no preferences exist
            return Response({}, status=status.HTTP_200_OK)

    def post(self, request):
        """
        Save or update the current user's layout preferences
        """
        try:
            # Get or create the layout preference
            layout_preference, created = LayoutPreference.objects.get_or_create(
                user=request.user
            )
            
            # Update the layout data
            layout_preference.layout = request.data
            layout_preference.save()
            
            return Response(
                {
                    'success': True,
                    'message': 'Layout preferences saved successfully',
                    'layout': layout_preference.layout
                }, 
                status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response(
                {
                    'success': False,
                    'error': str(e)
                }, 
                status=status.HTTP_400_BAD_REQUEST
            )


# Alternative Django view for projects not using DRF
def layout_preference_view(request):
    """
    Django view for layout preferences (fallback if DRF is not available)
    """
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required'}, status=401)
    
    if request.method == 'GET':
        try:
            layout_preference = LayoutPreference.objects.get(user=request.user)
            return JsonResponse(layout_preference.layout)
        except LayoutPreference.DoesNotExist:
            return JsonResponse({})
    
    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
            layout_preference, created = LayoutPreference.objects.get_or_create(
                user=request.user
            )
            layout_preference.layout = data
            layout_preference.save()
            
            return JsonResponse({
                'success': True,
                'message': 'Layout preferences saved successfully',
                'layout': layout_preference.layout
            })
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=400)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)
