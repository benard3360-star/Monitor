from django.contrib.auth import get_user_model
from rest_framework import serializers

from .models import AlertCase, CaseActivity, InAppNotification
from .security_utils import mask_account_identifier

User = get_user_model()


class CaseActivitySerializer(serializers.ModelSerializer):
    actor_username = serializers.SerializerMethodField()

    class Meta:
        model = CaseActivity
        fields = (
            "id",
            "action",
            "message",
            "payload",
            "actor_username",
            "created_at",
        )
        read_only_fields = fields

    def get_actor_username(self, obj):
        return obj.actor.get_username() if obj.actor_id else None


class AlertCaseSerializer(serializers.ModelSerializer):
    activities = CaseActivitySerializer(many=True, read_only=True)
    assignee_username = serializers.SerializerMethodField()
    account_id = serializers.SerializerMethodField()
    receiver_account = serializers.SerializerMethodField()
    assigned_user = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.filter(is_active=True),
        allow_null=True,
        required=False,
    )

    class Meta:
        model = AlertCase
        fields = (
            "id",
            "probability",
            "risk_level",
            "rules",
            "flagged",
            "alert",
            "case_status",
            "assigned_to",
            "assigned_user",
            "assignee_username",
            "account_id",
            "receiver_account",
            "amount",
            "country",
            "source",
            "investigation_notes",
            "txn_timestamp",
            "created_at",
            "updated_at",
            "activities",
        )
        read_only_fields = (
            "id",
            "probability",
            "risk_level",
            "rules",
            "flagged",
            "alert",
            "account_id",
            "receiver_account",
            "amount",
            "country",
            "source",
            "created_at",
            "updated_at",
            "activities",
            "assigned_to",
            "assignee_username",
        )
        extra_kwargs = {
            "case_status": {"required": False},
            "investigation_notes": {"required": False},
        }

    def get_assignee_username(self, obj):
        if obj.assigned_user_id:
            return obj.assigned_user.get_username()
        return obj.assigned_to or None

    def get_account_id(self, obj):
        return mask_account_identifier(obj.account_id)

    def get_receiver_account(self, obj):
        return mask_account_identifier(obj.receiver_account)


class AlertCaseListSerializer(serializers.ModelSerializer):
    assignee_username = serializers.SerializerMethodField()
    account_id = serializers.SerializerMethodField()
    receiver_account = serializers.SerializerMethodField()

    class Meta:
        model = AlertCase
        fields = (
            "id",
            "probability",
            "risk_level",
            "rules",
            "case_status",
            "assigned_to",
            "assignee_username",
            "account_id",
            "receiver_account",
            "amount",
            "txn_timestamp",
            "created_at",
            "updated_at",
        )

    def get_assignee_username(self, obj):
        if obj.assigned_user_id:
            return obj.assigned_user.get_username()
        return obj.assigned_to or None

    def get_account_id(self, obj):
        return mask_account_identifier(obj.account_id)

    def get_receiver_account(self, obj):
        return mask_account_identifier(obj.receiver_account)


class InAppNotificationSerializer(serializers.ModelSerializer):
    alert_case_id = serializers.IntegerField(source="alert_case_id", read_only=True, allow_null=True)

    class Meta:
        model = InAppNotification
        fields = ("id", "message", "read", "alert_case_id", "created_at")
        read_only_fields = ("id", "message", "alert_case_id", "created_at")
