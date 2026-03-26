from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import rest_views
from .ui_views import (
    FinGuardLoginView,
    case_detail_page,
    case_list_page,
    monitoring_dashboard,
    user_management_page,
)
from .views import (
    alert_action,
    alerts,
    alerts_data,
    alerts_page,
    analytics_data,
    analytics_page,
    analyze_transactions_status,
    analyze_transactions_submit,
    audit_log_page,
    audit_logs_data,
    case_management_page,
    cases_data,
    chat_ask,
    chat_page,
    dashboard_data,
    client_insights_data,
    explorer_data,
    home,
    settings_data,
    settings_page,
    transaction_explorer_page,
    transactions,
)

router = DefaultRouter()
router.register(r"v1/alerts", rest_views.AlertCaseViewSet, basename="alertcase")
router.register(r"v1/notifications", rest_views.NotificationViewSet, basename="notification")

urlpatterns = [
    path("", home, name="home"),
    path("dashboard/", home, name="dashboard_page"),
    path("monitoring/", monitoring_dashboard, name="monitoring_dashboard"),
    path("users/", user_management_page, name="user_management_page"),
    path("cases/", case_list_page, name="case_list_page"),
    path("cases/<int:pk>/", case_detail_page, name="case_detail_page"),
    path("cases-legacy/", case_management_page, name="cases_page"),
    path("alerts-page/", alerts_page, name="alerts_page"),
    path("explorer/", transaction_explorer_page, name="explorer_page"),
    path("analytics/", analytics_page, name="analytics_page"),
    path("chat/", chat_page, name="chat_page"),
    path("settings-page/", settings_page, name="settings_page"),
    path("audit-log/", audit_log_page, name="audit_log_page"),
    path("analyze/submit/", analyze_transactions_submit, name="analyze_transactions_submit"),
    path(
        "analyze/status/<str:job_id>/",
        analyze_transactions_status,
        name="analyze_transactions_status",
    ),
    path("api/", include(router.urls)),
    path("api/v1/users/", rest_views.compliance_user_directory, name="api_compliance_users"),
    path("api/dashboard-data/", dashboard_data, name="dashboard_data"),
    path("api/client-insights/", client_insights_data, name="client_insights_data"),
    path("api/analytics-data/", analytics_data, name="analytics_data"),
    path("api/alerts-data/", alerts_data, name="alerts_data"),
    path("api/alerts/<int:alert_id>/action/", alert_action, name="alert_action"),
    path("api/cases-data/", cases_data, name="cases_data"),
    path("api/explorer-data/", explorer_data, name="explorer_data"),
    path("api/settings/", settings_data, name="settings_data"),
    path("api/audit-logs/", audit_logs_data, name="audit_logs_data"),
    path("api/chat/ask/", chat_ask, name="chat_ask"),
    path("transactions/", transactions, name="transactions"),
    path("alerts/", alerts, name="alerts"),
]
