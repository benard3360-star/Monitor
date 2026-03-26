import io
from pathlib import Path
from decimal import Decimal, InvalidOperation

from django.conf import settings
from django.core.cache import cache
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Ingest transactions_dataset.csv into SQLite and precompute AML alerts/metrics."

    def add_arguments(self, parser):
        parser.add_argument(
            "--path",
            default=str(Path(settings.BASE_DIR) / "transactions_dataset.csv"),
            help="Path to transactions_dataset.csv",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Recompute and overwrite dataset-based alerts even if they exist.",
        )

    def handle(self, *args, **options):
        from api.models import AlertCase, Transaction
        from api import views as aml_views

        dataset_path = Path(options["path"])
        if not dataset_path.exists():
            raise FileNotFoundError(f"CSV not found: {dataset_path}")

        dataset_source = getattr(aml_views, "_DATASET_SOURCE", "dataset")
        existing = AlertCase.objects.filter(source=dataset_source).exists()
        caches_ready = aml_views.aml_caches_ready()
        if existing and not options["force"] and caches_ready:
            self.stdout.write(
                self.style.SUCCESS(
                    f"Dataset already ingested for source={dataset_source} and caches are warm. "
                    "Use --force to recompute from CSV."
                )
            )
            return

        if existing and not options["force"] and not caches_ready:
            self.stdout.write(
                self.style.WARNING(
                    "Dataset rows exist but analysis/analytics cache is missing or outdated; rebuilding from CSV..."
                )
            )

        self.stdout.write(self.style.WARNING("Loading dataset and scoring..."))

        file_bytes = dataset_path.read_bytes()
        file_like = io.BytesIO(file_bytes)
        rows = aml_views._parse_csv(file_like)

        model, preprocessor, threshold = aml_views._load_artifacts()
        probabilities = aml_views._predict_probabilities(rows, model, preprocessor)

        result = aml_views._build_analysis_response(rows, probabilities, threshold)
        aml_views._persist_alert_cases(
            aml_views._build_case_rows(rows, probabilities, threshold),
            source=dataset_source,
        )

        # Full dataset persistence for account-level querying/reporting.
        self.stdout.write(self.style.WARNING("Refreshing Transaction table from full dataset..."))
        Transaction.objects.all().delete()
        tx_batch = []
        batch_size = 5000
        for row in rows:
            account_id = str(
                row.get("Sender_account") or row.get("account_id") or ""
            ).strip()[:64]
            amount_raw = row.get("Amount") or row.get("amount") or "0"
            try:
                amount = Decimal(str(amount_raw))
            except (InvalidOperation, ValueError, TypeError):
                amount = Decimal("0")
            currency = str(
                row.get("Payment_currency")
                or row.get("payment_currency")
                or row.get("currency_from")
                or row.get("sender_currency")
                or "USD"
            ).strip()[:8] or "USD"
            transaction_type = str(
                row.get("Payment_type")
                or row.get("payment_type")
                or row.get("transaction_type")
                or "transfer"
            ).strip()[:32] or "transfer"
            sender_loc = str(
                row.get("Sender_bank_location") or row.get("sender_country") or ""
            ).strip()
            receiver_loc = str(
                row.get("Receiver_bank_location") or row.get("receiver_country") or ""
            ).strip()
            receiver_account = str(
                row.get("Receiver_account") or row.get("receiver_account") or ""
            ).strip()
            received_currency = str(
                row.get("Received_currency") or row.get("received_currency") or ""
            ).strip()
            description = (
                f"receiver={receiver_account}|sender_loc={sender_loc}|"
                f"receiver_loc={receiver_loc}|received_currency={received_currency}"
            )[:1000]
            tx_batch.append(
                Transaction(
                    account_id=account_id,
                    amount=amount,
                    currency=currency,
                    transaction_type=transaction_type,
                    description=description,
                    is_suspicious=False,
                    suspicious_reason="",
                )
            )
            if len(tx_batch) >= batch_size:
                Transaction.objects.bulk_create(tx_batch, batch_size=batch_size)
                tx_batch = []
        if tx_batch:
            Transaction.objects.bulk_create(tx_batch, batch_size=batch_size)

        analytics = aml_views._compute_analytics(rows, probabilities, threshold)

        cache_payload = {
            "job_id": "dataset_ingest",
            "completed_at": aml_views.timezone.now().isoformat(),
            "result": result,
        }

        cache_timeout = aml_views._CACHE_TIMEOUT_SECONDS
        cache.set(aml_views._CACHE_LATEST_ANALYSIS_KEY, cache_payload, cache_timeout)
        cache.set(aml_views._CACHE_LATEST_ANALYTICS_KEY, analytics, cache_timeout)

        m = result.get("metrics", {})
        self.stdout.write(self.style.SUCCESS("Dataset ingest complete."))
        self.stdout.write(f"Total Transactions: {m.get('Total Transactions')}")
        self.stdout.write(f"Suspicious: {m.get('Suspicious')}")
        self.stdout.write(f"High Risk: {m.get('High Risk')}")
        self.stdout.write(f"Critical Risk: {m.get('Critical Risk')}")
        self.stdout.write(f"AlertCase rows stored: {AlertCase.objects.filter(source=dataset_source).count()}")
        self.stdout.write(f"Transaction rows stored: {Transaction.objects.count()}")

