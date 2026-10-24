from . import services


class BlockingRuleMiddleware:
    """Evaluate enabled blocking rules on every request (except /health/).

    Runs after WhiteNoise in the stack, so static files are unaffected.
    Operators are not exempt: a scanner UA on an operator path is exactly
    what these rules exist to catch - use the dry-run test page before
    enabling a rule that could match your own tooling.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith("/health/"):
            return self.get_response(request)
        ip = services.client_ip(request)
        blocked = services.evaluate_blocking_rules(request, ip)
        if blocked is not None:
            rule, fired = blocked
            return services.apply_blocking_rule(request, ip, rule, fired)
        return self.get_response(request)
