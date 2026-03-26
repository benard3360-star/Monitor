from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0002_alertcase_appsetting_auditlog"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterField(
            model_name="alertcase",
            name="case_status",
            field=models.CharField(
                choices=[
                    ("UNDER_REVIEW", "Under Review"),
                    ("CONFIRMED", "Confirmed Suspicious"),
                    ("FALSE_POSITIVE", "False Positive"),
                    ("ESCALATED", "Escalated"),
                ],
                db_index=True,
                default="UNDER_REVIEW",
                max_length=32,
            ),
        ),
        migrations.AddField(
            model_name="alertcase",
            name="assigned_user",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="assigned_alert_cases",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="alertcase",
            name="receiver_account",
            field=models.CharField(blank=True, db_index=True, max_length=64),
        ),
        migrations.AddField(
            model_name="alertcase",
            name="investigation_notes",
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name="alertcase",
            name="txn_timestamp",
            field=models.DateTimeField(blank=True, db_index=True, null=True),
        ),
        migrations.CreateModel(
            name="CaseActivity",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "action",
                    models.CharField(
                        choices=[
                            ("CREATED", "Case created / ingested"),
                            ("STATUS_CHANGED", "Status changed"),
                            ("ASSIGNED", "Assignment changed"),
                            ("NOTE_ADDED", "Investigation note updated"),
                            ("BULK_ASSIGNED", "Bulk assignment"),
                        ],
                        max_length=32,
                    ),
                ),
                ("message", models.TextField(blank=True)),
                ("payload", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                (
                    "actor",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="case_activities",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "alert_case",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="activities",
                        to="api.alertcase",
                    ),
                ),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.CreateModel(
            name="InAppNotification",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("message", models.CharField(max_length=512)),
                ("read", models.BooleanField(db_index=True, default=False)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                (
                    "alert_case",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="notifications",
                        to="api.alertcase",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="in_app_notifications",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={"ordering": ["-created_at"]},
        ),
    ]
