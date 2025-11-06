from django.http import JsonResponse


class JSONExceptionMiddleware:
    """
    Middleware that catches OTPWebAuthnApiError exceptions and returns
    JSON responses matching the previous DRF format.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_exception(self, request, exception):
        from django_otp_webauthn.exceptions import OTPWebAuthnApiError
        
        if isinstance(exception, OTPWebAuthnApiError):
            return JsonResponse(
                {
                    "detail": str(exception.default_detail),
                    "code": exception.default_code,
                },
                status=exception.status_code,
            )
        return None
