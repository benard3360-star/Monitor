from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Transaction",
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
                ("account_id", models.CharField(db_index=True, max_length=64)),
                ("amount", models.DecimalField(decimal_places=2, max_digits=12)),
                ("currency", models.CharField(default="USD", max_length=8)),
                ("transaction_type", models.CharField(default="transfer", max_length=32)),
                ("description", models.TextField(blank=True)),
                ("is_suspicious", models.BooleanField(default=False)),
                ("suspicious_reason", models.CharField(blank=True, max_length=255)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
            ],
            options={"ordering": ["-created_at"]},
        ),
    ]
