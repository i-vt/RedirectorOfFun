from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.http import JsonResponse
from django.views.decorators.cache import never_cache


@never_cache
def liveness(request):
    return JsonResponse({"status": "ok", "service": "redirector-control-plane"})


@never_cache
def readiness(request):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        executor = MigrationExecutor(connection)
        pending = executor.migration_plan(executor.loader.graph.leaf_nodes())
    except Exception:
        return JsonResponse({"status": "unavailable", "database": "error"}, status=503)
    if pending:
        return JsonResponse({"status": "unavailable", "database": "ready", "pending_migrations": len(pending)}, status=503)
    return JsonResponse({"status": "ready", "database": "ready", "pending_migrations": 0})
