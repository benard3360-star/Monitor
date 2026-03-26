from __future__ import annotations

from typing import Any

from .permissions import user_is_aml_admin, user_is_compliance_officer


def fing_flags(request: Any) -> dict[str, Any]:
    """
    Expose RBAC flags to templates without repeating query logic.
    """
    user = getattr(request, "user", None)
    return {
        "is_aml_admin": user_is_aml_admin(user),
        "is_compliance_officer": user_is_compliance_officer(user),
    }

