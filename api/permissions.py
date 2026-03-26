from rest_framework.permissions import BasePermission

AML_ADMIN_GROUP = "AML Admin"
COMPLIANCE_OFFICER_GROUP = "Compliance Officer"


def user_is_aml_admin(user) -> bool:
    if not user or not user.is_authenticated:
        return False
    if user.is_superuser:
        return True
    return user.groups.filter(name=AML_ADMIN_GROUP).exists()


def user_is_compliance_officer(user) -> bool:
    if not user or not user.is_authenticated:
        return False
    if getattr(user, "is_superuser", False):
        return True
    if user_is_aml_admin(user):
        return True
    return user.groups.filter(name=COMPLIANCE_OFFICER_GROUP).exists()


class IsComplianceOfficer(BasePermission):
    """AML Admin or Compliance Officer may access monitoring and case APIs."""

    def has_permission(self, request, view):
        u = request.user
        return bool(u and u.is_authenticated and user_is_compliance_officer(u))


class IsAMLAdmin(BasePermission):
    """AML Admin (or superuser) — assignments, bulk ops, user list, threshold POST."""

    def has_permission(self, request, view):
        u = request.user
        return bool(u and u.is_authenticated and user_is_aml_admin(u))
