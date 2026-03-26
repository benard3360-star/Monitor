from django.contrib import admin

from .models import (
    AlertCase,
    AppSetting,
    AuditLog,
    CaseActivity,
    InAppNotification,
    Transaction,
)


@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "account_id",
        "amount",
        "currency",
        "transaction_type",
        "is_suspicious",
        "created_at",
    )
    list_filter = ("is_suspicious", "currency", "transaction_type")
    search_fields = ("account_id", "description", "suspicious_reason")


@admin.register(AlertCase)
class AlertCaseAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "probability",
        "risk_level",
        "case_status",
        "assigned_to",
        "assigned_user",
        "account_id",
        "receiver_account",
        "created_at",
    )
    list_filter = ("risk_level", "case_status", "flagged", "source")
    search_fields = ("account_id", "receiver_account", "assigned_to", "rules")
    raw_id_fields = ("assigned_user",)


@admin.register(CaseActivity)
class CaseActivityAdmin(admin.ModelAdmin):
    list_display = ("id", "alert_case", "action", "actor", "created_at")
    list_filter = ("action",)
    raw_id_fields = ("alert_case", "actor")


@admin.register(InAppNotification)
class InAppNotificationAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "read", "message", "created_at")
    list_filter = ("read",)
    raw_id_fields = ("user", "alert_case")


@admin.register(AppSetting)
class AppSettingAdmin(admin.ModelAdmin):
    list_display = ("key", "value", "updated_at")
    search_fields = ("key",)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("action", "actor", "created_at")
    search_fields = ("action", "details", "actor")
