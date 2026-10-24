from rest_framework.pagination import CursorPagination, PageNumberPagination


class EventCursorPagination(CursorPagination):
    page_size = 50
    ordering = ("-occurred_at", "-id")
    cursor_query_param = "cursor"


class HitCursorPagination(CursorPagination):
    page_size = 50
    ordering = ("-created_at", "-id")
    cursor_query_param = "cursor"


class AuditCursorPagination(CursorPagination):
    page_size = 50
    ordering = ("-created_at", "-id")
    cursor_query_param = "cursor"


class OperatorPagination(PageNumberPagination):
    page_size = 50
