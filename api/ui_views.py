"""Server-rendered FinGuard monitoring and case management pages (Bootstrap)."""

from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LogoutView
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.shortcuts import get_object_or_404, render

from .models import AlertCase
from .permissions import user_is_aml_admin, user_is_compliance_officer


class FinGuardLoginView(auth_views.LoginView):
    template_name = "api/login.html"
    redirect_authenticated_user = True

    def get_success_url(self):
        # Always land in the app UI, not Django admin (ignore ?next=/admin/...).
        return "/monitoring/"


class FinGuardLogoutView(LogoutView):
    """Allow GET so navbar link works without a form."""

    next_page = "/login/"
    http_method_names = ["get", "post", "head", "options"]

    def get_next_page(self):
        # Ignore any incoming ?next=... (e.g. /admin/) and always go to our login page.
        return self.next_page


@login_required
def monitoring_dashboard(request):
    if not user_is_compliance_officer(request.user):
        return render(
            request,
            "api/access_denied.html",
            {"message": "Your account needs the Compliance Officer or AML Admin role."},
            status=403,
        )
    return render(
        request,
        "api/monitoring_dashboard.html",
        {"is_aml_admin": user_is_aml_admin(request.user)},
    )


@login_required
def case_list_page(request):
    if not user_is_compliance_officer(request.user):
        return render(
            request,
            "api/access_denied.html",
            {"message": "Your account needs the Compliance Officer or AML Admin role."},
            status=403,
        )
    return render(
        request,
        "api/case_list.html",
        {"is_aml_admin": user_is_aml_admin(request.user)},
    )


@login_required
def case_detail_page(request, pk: int):
    if not user_is_compliance_officer(request.user):
        return render(
            request,
            "api/access_denied.html",
            {"message": "Your account needs the Compliance Officer or AML Admin role."},
            status=403,
        )
    case = get_object_or_404(AlertCase, pk=pk)
    return render(
        request,
        "api/case_detail.html",
        {
            "case_id": case.id,
            "is_aml_admin": user_is_aml_admin(request.user),
        },
    )


@login_required
def user_management_page(request):
    """
    AML Admin only: create staff users and assign them to groups so they can
    receive automatically-assigned cases/alerts.
    """
    if not user_is_aml_admin(request.user):
        return render(
            request,
            "api/access_denied.html",
            {"message": "AML Admin role required to manage users."},
            status=403,
        )

    User = get_user_model()

    users = User.objects.all().order_by("username")
    all_groups = Group.objects.all().order_by("name")
    compliance_group = all_groups.filter(name="Compliance Officer").first()

    msg = ""
    if request.method == "POST":
        username = (request.POST.get("username") or "").strip()
        email = (request.POST.get("email") or "").strip()
        password = request.POST.get("password") or ""
        group_ids = request.POST.getlist("groups") or []

        if not username or not password:
            msg = "Username and password are required."
        elif User.objects.filter(username=username).exists():
            msg = "Username already exists."
        else:
            u = User.objects.create_user(
                username=username,
                email=email,
                password=password,
            )
            u.is_active = True
            # Allow login through our staff authentication flow.
            u.is_staff = True
            u.save()

            if group_ids:
                u.groups.set(Group.objects.filter(id__in=group_ids))
            elif compliance_group:
                u.groups.add(compliance_group)

            msg = f"User {u.username} created successfully."
            users = User.objects.all().order_by("username")

    return render(
        request,
        "api/user_management.html",
        {
            "users": users,
            "all_groups": all_groups,
            "msg": msg,
            "is_aml_admin": True,
        },
    )
