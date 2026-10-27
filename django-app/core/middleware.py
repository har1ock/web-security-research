
from django.conf import settings

def csp_middleware(get_response):
    """Додає CSP лише в режимі P. Те саме що after_request у Flask."""
    def middleware(request):
        response = get_response(request)
        if settings.SECURE:
            response["Content-Security-Policy"] = (
                "default-src 'self'; object-src 'none'; frame-ancestors 'none'" 
            )
        return response
    return middleware