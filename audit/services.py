from .models import AuditEvent


def record_event(*, action, actor=None, target=None, metadata=None, request=None):
    """Create an audit record; callers wrap privileged mutations in a transaction."""
    return AuditEvent.objects.create(
        actor=actor if getattr(actor, "is_authenticated", False) else None,
        action=action,
        target_type=target.__class__.__name__ if target is not None else "",
        target_id=str(target.pk) if target is not None and target.pk is not None else "",
        request_id=getattr(request, "request_id", ""),
        source_ip=request.META.get("REMOTE_ADDR") if request else None,
        metadata=metadata or {},
    )
