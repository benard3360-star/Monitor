from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="AlertCase",
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
                ("probability", models.FloatField()),
                ("risk_level", models.CharField(db_index=True, max_length=16)),
                ("rules", models.TextField(blank=True)),
                ("flagged", models.BooleanField(db_index=True, default=True)),
                (
                    "alert",
                    models.CharField(
                        default="Potential Money Laundering", max_length=128
                    ),
                ),
                (
                    "case_status",
                    models.CharField(
                        choices=[
                            ("UNDER_REVIEW", "Under Review"),
                            ("CONFIRMED", "Confirmed Suspicious"),
                            ("FALSE_POSITIVE", "False Positive"),
                        ],
                        db_index=True,
                        default="UNDER_REVIEW",
                        max_length=32,
                    ),
                ),
                ("assigned_to", models.CharField(blank=True, max_length=128)),
                ("account_id", models.CharField(blank=True, db_index=True, max_length=64)),
                (
                    "amount",
                    models.DecimalField(
                        blank=True, decimal_places=2, max_digits=12, null=True
                    ),
                ),
                ("country", models.CharField(blank=True, max_length=64)),
                ("source", models.CharField(default="upload", max_length=32)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.CreateModel(
            name="AppSetting",
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
                ("key", models.CharField(max_length=128, unique=True)),
                ("value", models.CharField(max_length=512)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name="AuditLog",
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
                ("action", models.CharField(max_length=128)),
                ("details", models.TextField(blank=True)),
                ("actor", models.CharField(default="system", max_length=128)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
            ],
            options={"ordering": ["-created_at"]},
        ),
    ]
