from __future__ import annotations

import logging

from django.contrib.auth import get_user_model
from django.db.models import Prefetch, Q, Value
from django.db.models.functions import Replace, Upper
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.pagination import PageNumberPagination
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response

from .models import AlertCase, AuditLog, CaseActivity, InAppNotification
from .permissions import (
    IsAMLAdmin,
    IsComplianceOfficer,
    user_is_aml_admin,
    user_is_compliance_officer,
)
from .serializers import (
    AlertCaseListSerializer,
    AlertCaseSerializer,
    InAppNotificationSerializer,
)

User = get_user_model()
logger = logging.getLogger(__name__)


class StandardResultsPagination(PageNumberPagination):
    page_size = 50
    page_size_query_param = "page_size"
    max_page_size = 200


def _log_audit(action: str, details: str, actor) -> None:
    try:
        AuditLog.objects.create(
            action=action,
            details=details[:2000],
            actor=actor.get_username() if getattr(actor, "is_authenticated", False) else "system",
        )
    except Exception:
        pass


def _notify_assignment(case: AlertCase, assigned: User | None, actor) -> None:
    if not assigned:
        return
    msg = f"You were assigned alert case #{case.id} ({case.risk_level} risk)."
    try:
        InAppNotification.objects.create(user=assigned, message=msg, alert_case=case)
    except Exception:
        logger.exception("In-app notification failed")
    try:
        from django.conf import settings
        from django.core.mail import send_mail

        if getattr(settings, "AML_ASSIGNMENT_EMAIL", False) and assigned.email:
            send_mail(
                subject=f"[FinGuard] Case #{case.id} assigned to you",
                message=msg,
                from_email=getattr(settings, "DEFAULT_FROM_EMAIL", None) or "noreply@localhost",
                recipient_list=[assigned.email],
                fail_silently=True,
            )
    except Exception:
        pass


def _record_activity(
    case: AlertCase,
    action: str,
    message: str,
    actor,
    payload: dict | None = None,
) -> None:
    CaseActivity.objects.create(
        alert_case=case,
        actor=actor if getattr(actor, "is_authenticated", False) else None,
        action=action,
        message=message,
        payload=payload or {},
    )


class AlertCaseViewSet(viewsets.ModelViewSet):
    """
    FinGuard alerts / cases: list, retrieve, partial_update.
    Compliance Officers: filter, update status & notes.
    AML Admins: assign / reassign (and bulk assign).
    """

    permission_classes = [IsComplianceOfficer]
    pagination_class = StandardResultsPagination
    http_method_names = ["get", "head", "options", "patch", "post"]
    queryset = (
        AlertCase.objects.all()
        .select_related("assigned_user")
        .prefetch_related(
            Prefetch(
                "activities",
                queryset=CaseActivity.objects.select_related("actor").order_by("created_at"),
            )
        )
        .order_by("-created_at")
    )

    def get_serializer_class(self):
        if self.action == "list":
            return AlertCaseListSerializer
        return AlertCaseSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        p = self.request.query_params
        if risk := p.get("risk_level"):
            qs = qs.filter(risk_level=risk)
        if st := p.get("case_status"):
            qs = qs.filter(case_status=st)
        if p.get("assigned_to_me") in ("1", "true", "yes"):
            u = self.request.user
            qs = qs.filter(Q(assigned_user=u) | Q(assigned_to=u.get_username()))
        if uid := p.get("assigned_user_id"):
            try:
                qs = qs.filter(assigned_user_id=int(uid))
            except ValueError:
                pass
        if df := p.get("date_from"):
            qs = qs.filter(created_at__date__gte=df)
        if dt := p.get("date_to"):
            qs = qs.filter(created_at__date__lte=dt)
        if tdf := p.get("txn_date_from"):
            qs = qs.filter(txn_timestamp__date__gte=tdf)
        if tdt := p.get("txn_date_to"):
            qs = qs.filter(txn_timestamp__date__lte=tdt)
        return qs

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        old_status = instance.case_status
        old_notes = instance.investigation_notes or ""
        old_assignee_id = instance.assigned_user_id
        old_assign_name = instance.assigned_to

        try:
            data = request.data.copy()
        except AttributeError:
            data = dict(request.data)
        if not user_is_aml_admin(request.user):
            data.pop("assigned_user", None)
            if isinstance(data, dict):
                data.pop("assigned_user_id", None)

        serializer = self.get_serializer(instance, data=data, partial=partial)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        instance.refresh_from_db()
        assign_changed = old_assignee_id != instance.assigned_user_id
        instance.sync_assigned_to_display()
        instance.save(update_fields=["assigned_to"])

        user = request.user
        if instance.case_status != old_status:
            _record_activity(
                instance,
                CaseActivity.Action.STATUS_CHANGED,
                f"Status: {old_status} → {instance.case_status}",
                user,
                {"from": old_status, "to": instance.case_status},
            )
        notes = instance.investigation_notes or ""
        if notes != old_notes:
            _record_activity(
                instance,
                CaseActivity.Action.NOTE_ADDED,
                "Investigation notes updated",
                user,
                {"length": len(notes)},
            )
        if assign_changed:
            nu = instance.assigned_user
            _record_activity(
                instance,
                CaseActivity.Action.ASSIGNED,
                f"Assigned to {nu.get_username() if nu else instance.assigned_to or '—'}",
                user,
                {"assigned_user_id": instance.assigned_user_id},
            )
            _notify_assignment(instance, nu, user)

        _log_audit(
            "CASE_UPDATED",
            f"Case {instance.id} updated by {user.get_username()}",
            user,
        )
        return Response(self.get_serializer(instance).data)

    @action(detail=False, methods=["get"], permission_classes=[IsComplianceOfficer])
    def summary(self, request):
        """Dashboard KPIs for case workflow."""
        base = AlertCase.objects.all()
        if not user_is_aml_admin(request.user):
            u = request.user
            base = base.filter(Q(assigned_user=u) | Q(assigned_to=u.get_username()))
        total_assigned = base.filter(
            Q(assigned_user__isnull=False) | ~Q(assigned_to="")
        ).count()

        # Normalize status text so legacy values (e.g. "Open", "Under Review")
        # are counted in the expected KPI buckets.
        normalized_status = base.annotate(
            norm_status=Upper(
                Replace(
                    Replace("case_status", Value(" "), Value("_")),
                    Value("-"),
                    Value("_"),
                )
            )
        )
        pending_review = normalized_status.filter(
            norm_status__in=["UNDER_REVIEW", "OPEN"]
        ).count()
        confirmed = normalized_status.filter(
            norm_status__in=["CONFIRMED", "CONFIRMED_SUSPICIOUS", "TRUE_POSITIVE"]
        ).count()
        false_positives = normalized_status.filter(
            norm_status__in=["FALSE_POSITIVE", "FALSEPOSITIVE"]
        ).count()
        escalated = normalized_status.filter(norm_status="ESCALATED").count()
        resolved = normalized_status.filter(
            norm_status__in=["RESOLVED", "CLOSED"]
        ).count()

        return Response(
            {
                "total_in_view": base.count(),
                "total_assigned": total_assigned,
                "pending_review": pending_review,
                "confirmed_suspicious": confirmed,
                "false_positives": false_positives,
                "escalated": escalated,
                "resolved": resolved,
            }
        )

    @action(
        detail=False,
        methods=["post"],
        permission_classes=[IsAMLAdmin],
    )
    def bulk_assign(self, request):
        ids = request.data.get("alert_ids") or []
        user_id = request.data.get("user_id")
        if not ids or not user_id:
            return Response(
                {"error": "alert_ids and user_id are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            assignee = User.objects.get(pk=int(user_id), is_active=True)
        except (User.DoesNotExist, ValueError):
            return Response({"error": "Invalid user_id."}, status=status.HTTP_400_BAD_REQUEST)
        updated = 0
        for pk in ids:
            try:
                case = AlertCase.objects.get(pk=int(pk))
            except (AlertCase.DoesNotExist, ValueError):
                continue
            case.assigned_user = assignee
            case.sync_assigned_to_display()
            case.save(update_fields=["assigned_user", "assigned_to", "updated_at"])
            _record_activity(
                case,
                CaseActivity.Action.BULK_ASSIGNED,
                f"Bulk-assigned to {assignee.get_username()}",
                request.user,
                {"bulk": True},
            )
            _notify_assignment(case, assignee, request.user)
            updated += 1
        _log_audit("BULK_ASSIGN", f"{updated} cases → user {assignee.id}", request.user)
        return Response({"updated": updated})


class NotificationViewSet(viewsets.ModelViewSet):
    permission_classes = [IsComplianceOfficer]
    serializer_class = InAppNotificationSerializer
    http_method_names = ["get", "head", "options", "patch"]

    def get_queryset(self):
        return InAppNotification.objects.filter(user=self.request.user).order_by("-created_at")

    def partial_update(self, request, *args, **kwargs):
        kwargs["partial"] = True
        n = self.get_object()
        if "read" in request.data:
            n.read = bool(request.data.get("read"))
            n.save(update_fields=["read"])
        return Response(self.get_serializer(n).data)


@api_view(["GET"])
@permission_classes([IsAMLAdmin])
def compliance_user_directory(request):
    """Assignable users (AML Admin only)."""
    users = User.objects.filter(is_active=True).order_by("username")
    return Response(
        {
            "results": [
                {"id": u.id, "username": u.get_username(), "email": u.email or ""}
                for u in users[:200]
            ]
        }
    )
