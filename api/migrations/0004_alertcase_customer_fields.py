from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0003_finguard_case_management"),
    ]

    operations = [
        migrations.AddField(
            model_name="alertcase",
            name="payment_currency",
            field=models.CharField(blank=True, max_length=32),
        ),
        migrations.AddField(
            model_name="alertcase",
            name="payment_type",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AddField(
            model_name="alertcase",
            name="received_currency",
            field=models.CharField(blank=True, max_length=32),
        ),
        migrations.AddField(
            model_name="alertcase",
            name="receiver_bank_location",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AddField(
            model_name="alertcase",
            name="sender_bank_location",
            field=models.CharField(blank=True, max_length=64),
        ),
    ]
