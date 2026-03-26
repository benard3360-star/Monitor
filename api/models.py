from django.conf import settings
from django.db import models


class Transaction(models.Model):
    account_id = models.CharField(max_length=64, db_index=True)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.CharField(max_length=8, default="USD")
    transaction_type = models.CharField(max_length=32, default="transfer")
    description = models.TextField(blank=True)
    is_suspicious = models.BooleanField(default=False)
    suspicious_reason = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.account_id} - {self.amount} {self.currency}"


class AlertCase(models.Model):
    STATUS_UNDER_REVIEW = "UNDER_REVIEW"
    STATUS_CONFIRMED = "CONFIRMED"
    STATUS_FALSE_POSITIVE = "FALSE_POSITIVE"
    STATUS_ESCALATED = "ESCALATED"
    STATUS_RESOLVED = "RESOLVED"
    STATUS_CHOICES = [
        (STATUS_UNDER_REVIEW, "Under Review"),
        (STATUS_CONFIRMED, "Confirmed Suspicious"),
        (STATUS_FALSE_POSITIVE, "False Positive"),
        (STATUS_ESCALATED, "Escalated"),
        (STATUS_RESOLVED, "Resolved"),
    ]

    probability = models.FloatField()
    risk_level = models.CharField(max_length=16, db_index=True)
    rules = models.TextField(blank=True)
    flagged = models.BooleanField(default=True, db_index=True)
    alert = models.CharField(max_length=128, default="Potential Money Laundering")
    case_status = models.CharField(
        max_length=32, choices=STATUS_CHOICES, default=STATUS_UNDER_REVIEW, db_index=True
    )
    assigned_to = models.CharField(
        max_length=128,
        blank=True,
        help_text="Legacy display name; prefer assigned_user when set.",
    )
    assigned_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="assigned_alert_cases",
    )
    account_id = models.CharField(max_length=64, blank=True, db_index=True)
    receiver_account = models.CharField(max_length=64, blank=True, db_index=True)
    payment_currency = models.CharField(max_length=32, blank=True)
    received_currency = models.CharField(max_length=32, blank=True)
    sender_bank_location = models.CharField(max_length=64, blank=True)
    receiver_bank_location = models.CharField(max_length=64, blank=True)
    payment_type = models.CharField(max_length=64, blank=True)
    amount = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    country = models.CharField(max_length=64, blank=True)
    source = models.CharField(max_length=32, default="upload")
    investigation_notes = models.TextField(blank=True)
    txn_timestamp = models.DateTimeField(null=True, blank=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def sync_assigned_to_display(self):
        if self.assigned_user_id:
            self.assigned_to = self.assigned_user.get_username()


class CaseActivity(models.Model):
    class Action(models.TextChoices):
        CREATED = "CREATED", "Case created / ingested"
        STATUS_CHANGED = "STATUS_CHANGED", "Status changed"
        ASSIGNED = "ASSIGNED", "Assignment changed"
        NOTE_ADDED = "NOTE_ADDED", "Investigation note updated"
        BULK_ASSIGNED = "BULK_ASSIGNED", "Bulk assignment"

    alert_case = models.ForeignKey(
        AlertCase, on_delete=models.CASCADE, related_name="activities"
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="case_activities",
    )
    action = models.CharField(max_length=32, choices=Action.choices)
    message = models.TextField(blank=True)
    payload = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]


class InAppNotification(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="in_app_notifications",
    )
    message = models.CharField(max_length=512)
    read = models.BooleanField(default=False, db_index=True)
    alert_case = models.ForeignKey(
        AlertCase,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="notifications",
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]


class AppSetting(models.Model):
    key = models.CharField(max_length=128, unique=True)
    value = models.CharField(max_length=512)
    updated_at = models.DateTimeField(auto_now=True)


class AuditLog(models.Model):
    action = models.CharField(max_length=128)
    details = models.TextField(blank=True)
    actor = models.CharField(max_length=128, default="system")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]
