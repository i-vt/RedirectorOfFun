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
        # Context is unknown here (view has not run); 404- and link-scoped
        # sets are evaluated again in the gate dispatcher with full context.
        decision = services.evaluate_blocking_rules(request, ip)
        if decision is not None:
            rule, fired = decision
            if rule.action == "allow":
                # count the match once, mark the request, and let it through;
                # the dispatcher must not re-evaluate (it would double-count)
                services.apply_blocking_rule(request, ip, rule, fired)
                request._rof_allowed = True
                return self.get_response(request)
            response = services.apply_blocking_rule(request, ip, rule, fired)
            if response is not None:
                return response
        return self.get_response(request)
