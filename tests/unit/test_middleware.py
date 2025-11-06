import pytest
from django.http import HttpResponse

from django_otp_webauthn.exceptions import (
    InvalidState,
    OTPWebAuthnApiError,
    PasswordlessLoginDisabled,
)
from django_otp_webauthn.middleware import JSONExceptionMiddleware


def test_middleware__handles_otp_webauthn_api_error(rf):
    """Test that the middleware catches OTPWebAuthnApiError and returns a JSON response."""

    def get_response(request):
        raise InvalidState()

    middleware = JSONExceptionMiddleware(get_response)
    request = rf.get("/")

    response = middleware.process_exception(request, InvalidState())

    assert response is not None
    assert response.status_code == 400
    assert response["Content-Type"] == "application/json"
    data = response.json()
    assert "detail" in data
    assert "code" in data
    assert data["code"] == "invalid_state"


def test_middleware__handles_passwordless_login_disabled(rf):
    """Test that the middleware catches PasswordlessLoginDisabled and returns a JSON response."""

    def get_response(request):
        raise PasswordlessLoginDisabled()

    middleware = JSONExceptionMiddleware(get_response)
    request = rf.get("/")

    response = middleware.process_exception(request, PasswordlessLoginDisabled())

    assert response is not None
    assert response.status_code == 403
    assert response["Content-Type"] == "application/json"
    data = response.json()
    assert "detail" in data
    assert "code" in data
    assert data["code"] == "passwordless_login_disabled"


def test_middleware__ignores_other_exceptions(rf):
    """Test that the middleware ignores exceptions that are not OTPWebAuthnApiError."""

    def get_response(request):
        raise ValueError("Some other error")

    middleware = JSONExceptionMiddleware(get_response)
    request = rf.get("/")

    response = middleware.process_exception(request, ValueError("Some other error"))

    assert response is None


def test_middleware__passes_through_normal_requests(rf):
    """Test that the middleware passes through normal requests without exceptions."""

    def get_response(request):
        return HttpResponse("OK")

    middleware = JSONExceptionMiddleware(get_response)
    request = rf.get("/")

    response = middleware(request)

    assert response.status_code == 200
    assert response.content == b"OK"
