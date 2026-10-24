from django.db import models


class NotFoundEvent(models.Model):
    request_id = models.CharField(max_length=64, unique=True)
    occurred_at = models.DateTimeField(db_index=True)
    method = models.CharField(max_length=10)
    path = models.TextField()
    status = models.PositiveSmallIntegerField(default=404, db_index=True)
    source_ip_hash = models.CharField(max_length=64, blank=True)
    country_code = models.CharField(max_length=2, blank=True)
    city = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-occurred_at"]
        indexes = [models.Index(fields=["occurred_at", "status"])]


class CollectorState(models.Model):
    key = models.CharField(max_length=200, unique=True)
    inode = models.BigIntegerField(null=True, blank=True)
    offset = models.BigIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)
