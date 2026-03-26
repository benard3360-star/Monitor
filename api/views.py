import csv
import io
import json
import logging
import pickle
import threading
import uuid
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.paginator import Paginator
from django.db.models import Count
from django.db.models.functions import TruncDate
from django.db.utils import OperationalError
from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from .models import AlertCase, AppSetting, AuditLog, Transaction
from .chatbot import answer_question
from .permissions import COMPLIANCE_OFFICER_GROUP, user_is_aml_admin
from .security_utils import mask_account_identifier

_MODEL = None
_PREPROCESSOR = None
_OPTIMAL_THRESHOLD = None
_ANALYSIS_JOBS = {}
_ANALYSIS_JOBS_LOCK = threading.Lock()

_CACHE_TIMEOUT_SECONDS = int(getattr(settings, "ML_CACHE_TIMEOUT_SECONDS", 3600))
_CACHE_LATEST_ANALYSIS_KEY = "aml:latest_analysis_result"
_CACHE_LATEST_ANALYTICS_KEY = "aml:latest_analysis_analytics"
_CACHE_LATEST_MODEL_INSIGHTS_KEY = "aml:latest_model_insights"

_DATASET_SOURCE = "dataset"
_DATASET_SYNC_LOCK = threading.Lock()

logger = logging.getLogger(__name__)


def analysis_cache_is_warm() -> bool:
    cached = cache.get(_CACHE_LATEST_ANALYSIS_KEY)
    if not cached or not cached.get("result"):
        return False
    metrics = (cached.get("result") or {}).get("metrics") or {}
    return metrics.get("Total Transactions") is not None


def analytics_cache_is_current() -> bool:
    """False when analytics payload predates schema changes (e.g. weekday chart)."""
    data = cache.get(_CACHE_LATEST_ANALYTICS_KEY)
    if not data or not isinstance(data, dict):
        return False
    return (
        "suspicious_by_weekday" in data
        and "critical_by_country" in data
        and "client_profiles" in data
    )


def aml_caches_ready() -> bool:
    return analysis_cache_is_warm() and analytics_cache_is_current()


def ensure_aml_dataset_ready() -> bool:
    """
    If the bundled CSV exists and analysis cache is empty, score the dataset,
    persist AlertCase rows, and populate analytics cache. Safe to call on every request;
    does a fast return when cache is already warm.
    """
    if not getattr(settings, "AML_AUTO_SYNC_DATASET", True):
        return aml_caches_ready()
    if aml_caches_ready():
        return True

    with _DATASET_SYNC_LOCK:
        if aml_caches_ready():
            return True

        csv_path = Path(getattr(settings, "AML_DATASET_CSV", settings.BASE_DIR / "transactions_dataset.csv"))
        if not csv_path.is_file():
            logger.warning("AML auto-sync skipped: CSV not found at %s", csv_path)
            return False

        try:
            file_bytes = csv_path.read_bytes()
            file_like = io.BytesIO(file_bytes)
            rows = _parse_csv(file_like)
            model, preprocessor, threshold = _load_artifacts()
            probabilities = _predict_probabilities(rows, model, preprocessor)
            if len(probabilities) != len(rows):
                raise RuntimeError("Model output does not match input row count.")
            result = _build_analysis_response(rows, probabilities, threshold)
            analytics = _compute_analytics(rows, probabilities, threshold)
            _persist_alert_cases(
                _build_case_rows(rows, probabilities, threshold),
                source=_DATASET_SOURCE,
                write_audit_log=False,
            )
            cache_payload = {
                "job_id": "auto_dataset_sync",
                "completed_at": timezone.now().isoformat(),
                "result": result,
            }
            cache.set(_CACHE_LATEST_ANALYSIS_KEY, cache_payload, _CACHE_TIMEOUT_SECONDS)
            cache.set(_CACHE_LATEST_ANALYTICS_KEY, analytics, _CACHE_TIMEOUT_SECONDS)
            cache.delete("aml:chat_kb_v1")
            try:
                AuditLog.objects.create(
                    action="DATASET_AUTO_SYNC",
                    details=f"Populated AML cache from {csv_path.name} ({len(rows)} rows).",
                    actor="system",
                )
            except Exception:
                pass
            return True
        except OperationalError as exc:
            logger.warning("AML auto-sync skipped (database not ready): %s", exc)
            return False
        except Exception:
            logger.exception("AML dataset auto-sync failed")
            return False


def home(request):
    return render(request, "api/dashboard.html")


def alerts_page(request):
    return render(request, "api/alerts.html")


def case_management_page(request):
    from django.shortcuts import redirect

    return redirect("case_list_page")


def transaction_explorer_page(request):
    return render(request, "api/explorer.html")


def analytics_page(request):
    return render(request, "api/analytics.html")


def chat_page(request):
    return render(request, "api/chat.html")


def model_insights_page(request):
    return render(request, "api/model_insights.html")


def settings_page(request):
    return render(request, "api/settings.html")


def audit_log_page(request):
    return render(request, "api/audit_log.html")


def _transaction_to_dict(transaction):
    return {
        "id": transaction.id,
        "account_id": transaction.account_id,
        "amount": str(transaction.amount),
        "currency": transaction.currency,
        "transaction_type": transaction.transaction_type,
        "description": transaction.description,
        "is_suspicious": transaction.is_suspicious,
        "suspicious_reason": transaction.suspicious_reason,
        "created_at": transaction.created_at.isoformat(),
    }


def _get_suspicious_reason(account_id, amount):
    if amount >= Decimal("10000.00"):
        return "High value transaction (>= 10000)"

    one_minute_ago = timezone.now() - timedelta(minutes=1)
    recent_count = Transaction.objects.filter(
        account_id=account_id, created_at__gte=one_minute_ago
    ).count()
    if recent_count >= 3:
        return "Too many transactions in under 1 minute"

    return ""


def _load_threshold_from_file():
    threshold_path = Path(
        getattr(
            settings,
            "ML_THRESHOLD_PATH",
            Path(settings.BASE_DIR) / "ml_artifacts" / "threshold.json",
        )
    )
    if not threshold_path.exists():
        return None

    try:
        with threshold_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        threshold = float(data.get("optimal_threshold"))
        return max(0.0, min(1.0, threshold))
    except (ValueError, TypeError, json.JSONDecodeError, OSError):
        return None


def _resolve_optimal_threshold(model):
    db_threshold = AppSetting.objects.filter(key="optimal_threshold").values_list(
        "value", flat=True
    ).first()
    if db_threshold is not None:
        try:
            return max(0.0, min(1.0, float(db_threshold)))
        except (ValueError, TypeError):
            pass

    configured_threshold = getattr(settings, "ML_OPTIMAL_THRESHOLD", None)
    if configured_threshold is not None:
        try:
            return max(0.0, min(1.0, float(configured_threshold)))
        except (ValueError, TypeError):
            pass

    model_threshold = getattr(model, "optimal_threshold", None)
    if model_threshold is not None:
        try:
            return max(0.0, min(1.0, float(model_threshold)))
        except (ValueError, TypeError):
            pass

    file_threshold = _load_threshold_from_file()
    if file_threshold is not None:
        return file_threshold

    return 0.5


def _load_artifacts():
    global _MODEL, _PREPROCESSOR, _OPTIMAL_THRESHOLD
    if _MODEL is not None and _PREPROCESSOR is not None:
        return _MODEL, _PREPROCESSOR, _OPTIMAL_THRESHOLD

    model_path = Path(
        getattr(
            settings,
            "ML_MODEL_PATH",
            Path(settings.BASE_DIR) / "ml_artifacts" / "model.pkl",
        )
    )
    preprocessor_path = Path(
        getattr(
            settings,
            "ML_PREPROCESSOR_PATH",
            Path(settings.BASE_DIR) / "ml_artifacts" / "preprocessor.pkl",
        )
    )
    if not model_path.exists() or not preprocessor_path.exists():
        raise FileNotFoundError(
            "Missing model artifacts. Expected files: "
            f"{model_path} and {preprocessor_path}."
        )

    _MODEL = _load_serialized_artifact(model_path)
    _PREPROCESSOR = _load_serialized_artifact(preprocessor_path)

    _OPTIMAL_THRESHOLD = _resolve_optimal_threshold(_MODEL)

    return _MODEL, _PREPROCESSOR, _OPTIMAL_THRESHOLD


def _load_serialized_artifact(path):
    errors = []

    # First try joblib, which is commonly used for sklearn pipelines/models.
    try:
        import joblib

        return joblib.load(path)
    except Exception as error:
        errors.append(f"joblib.load failed: {error}")

    # Then try standard pickle loading.
    try:
        with path.open("rb") as handle:
            return pickle.load(handle)
    except Exception as error:
        errors.append(f"pickle.load failed: {error}")

    # Finally try legacy compatibility for older Python 2 pickles.
    try:
        with path.open("rb") as handle:
            return pickle.load(handle, encoding="latin1")
    except Exception as error:
        errors.append(f"pickle.load latin1 failed: {error}")

    error_text = " | ".join(errors)
    raise RuntimeError(f"Unable to load artifact {path.name}. {error_text}")


def _parse_csv(uploaded_file):
    try:
        decoded = uploaded_file.read().decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ValueError("CSV must be UTF-8 encoded.") from error

    reader = csv.DictReader(io.StringIO(decoded))
    rows = list(reader)
    if not rows:
        raise ValueError("CSV file is empty or missing data rows.")
    if not reader.fieldnames:
        raise ValueError("CSV headers are missing.")
    return rows


def _to_float(value):
    try:
        return float(value)
    except (ValueError, TypeError):
        return 0.0


def _row_value(row, candidates):
    """Best-effort field lookup across naming styles."""
    if not isinstance(row, dict):
        return None
    for key in candidates:
        if key in row:
            return row.get(key)
    lowered = {str(k).lower(): v for k, v in row.items()}
    for key in candidates:
        value = lowered.get(str(key).lower())
        if value is not None:
            return value
    normalized = {
        str(k).lower().replace("_", "").replace(" ", ""): v for k, v in row.items()
    }
    for key in candidates:
        norm = str(key).lower().replace("_", "").replace(" ", "")
        value = normalized.get(norm)
        if value is not None:
            return value
    return None


def _collect_customer_fields_from_rows(rows, account_query):
    account_q = str(account_query or "").strip().lower()
    if not account_q:
        return {}
    payment_currency = set()
    received_currency = set()
    sender_bank_location = set()
    receiver_bank_location = set()
    payment_type_counts = {}

    for row in rows:
        account_id = str(_row_value(row, ["Sender_account", "account_id"]) or "").strip()
        if not account_id or account_q not in account_id.lower():
            continue

        pcur = str(
            _row_value(
                row,
                [
                    "Payment_currency",
                    "payment_currency",
                    "currency_from",
                    "sender_currency",
                    "Payment Currency",
                ],
            )
            or ""
        ).strip()
        rcur = str(
            _row_value(
                row,
                [
                    "Received_currency",
                    "received_currency",
                    "currency_to",
                    "receiver_currency",
                    "Received Currency",
                ],
            )
            or ""
        ).strip()
        sloc = str(
            _row_value(
                row,
                [
                    "Sender_bank_location",
                    "sender_bank_location",
                    "sender_country",
                    "Sender Bank Location",
                ],
            )
            or ""
        ).strip()
        rloc = str(
            _row_value(
                row,
                [
                    "Receiver_bank_location",
                    "receiver_bank_location",
                    "receiver_country",
                    "Receiver Bank Location",
                ],
            )
            or ""
        ).strip()
        ptype = str(
            _row_value(
                row,
                ["Payment_type", "payment_type", "transaction_type", "Payment Type"],
            )
            or ""
        ).strip()

        if pcur:
            payment_currency.add(pcur)
        if rcur:
            received_currency.add(rcur)
        if sloc:
            sender_bank_location.add(sloc)
        if rloc:
            receiver_bank_location.add(rloc)
        if ptype:
            payment_type_counts[ptype] = payment_type_counts.get(ptype, 0) + 1

    return {
        "payment_currency": sorted(payment_currency),
        "received_currency": sorted(received_currency),
        "sender_bank_location": sorted(sender_bank_location),
        "receiver_bank_location": sorted(receiver_bank_location),
        "payment_type": [
            {"type": k, "count": v}
            for k, v in sorted(payment_type_counts.items(), key=lambda x: x[1], reverse=True)
        ],
    }


def _load_customer_fields_from_dataset(account_query):
    csv_path = Path(
        getattr(settings, "AML_DATASET_CSV", settings.BASE_DIR / "transactions_dataset.csv")
    )
    if not csv_path.is_file():
        return {}
    try:
        decoded = csv_path.read_text(encoding="utf-8-sig")
        rows = list(csv.DictReader(io.StringIO(decoded)))
        return _collect_customer_fields_from_rows(rows, account_query)
    except Exception:
        return {}


def _load_dataset_client_snapshot(account_query):
    csv_path = Path(
        getattr(settings, "AML_DATASET_CSV", settings.BASE_DIR / "transactions_dataset.csv")
    )
    if not csv_path.is_file():
        return None
    try:
        decoded = csv_path.read_text(encoding="utf-8-sig")
        rows = list(csv.DictReader(io.StringIO(decoded)))
    except Exception:
        return None

    account_q = str(account_query or "").strip().lower()
    matched = []
    for row in rows:
        acc = str(_row_value(row, ["Sender_account", "account_id"]) or "").strip()
        if acc and account_q in acc.lower():
            matched.append(row)
    if not matched:
        return None

    fields = _collect_customer_fields_from_rows(matched, account_query)
    amounts = [_to_float(_row_value(r, ["Amount", "amount"])) for r in matched]
    day_counts = {}
    recent = []
    for row in matched[:200]:
        dt = _coerce_row_datetime(row)
        day = dt.date().isoformat() if dt else None
        if day:
            day_counts[day] = day_counts.get(day, 0) + 1
        recent.append(
            {
                "id": None,
                "sender_account": mask_account_identifier(
                    str(_row_value(row, ["Sender_account", "account_id"]) or "")
                ),
                "receiver_account": mask_account_identifier(
                    str(_row_value(row, ["Receiver_account", "receiver_account"]) or "")
                ),
                "amount": _to_float(_row_value(row, ["Amount", "amount"])),
                "country": str(
                    _row_value(row, ["Sender_bank_location", "sender_country"]) or "Unknown"
                ),
                "risk_level": "N/A",
                "probability": None,
                "status": "N/A",
                "timestamp": dt.isoformat() if dt else "",
            }
        )

    sender_locs = fields.get("sender_bank_location", []) or []
    origin_country = sender_locs[0] if sender_locs else "Unknown"
    return {
        "summary": {
            "total_cases": len(matched),
            "suspicious_cases": 0,
            "origin_country": origin_country,
            "countries_transacted_to": fields.get("receiver_bank_location", []) or [],
            "amount_summary": {
                "total": round(sum(amounts), 2) if amounts else 0.0,
                "average": round(sum(amounts) / len(amounts), 2) if amounts else 0.0,
                "max": round(max(amounts), 2) if amounts else 0.0,
            },
        },
        "customer_fields": {
            "payment_currency": fields.get("payment_currency", []) or [],
            "received_currency": fields.get("received_currency", []) or [],
            "sender_bank_location": fields.get("sender_bank_location", []) or [],
            "receiver_bank_location": fields.get("receiver_bank_location", []) or [],
            "payment_type": fields.get("payment_type", []) or [],
            "matched_account": mask_account_identifier(account_query),
        },
        "risk_distribution": {"Low": 0, "Medium": 0, "High": 0, "Critical": 0},
        "trend_by_day": [{"d": k, "count": v} for k, v in sorted(day_counts.items())],
        "top_counterparties": [],
        "recent_transactions": recent[:100],
    }


def _mask_alert_payload_accounts(item: dict) -> dict:
    """
    Return a shallow copy with sender/receiver account identifiers masked.
    """
    out = dict(item)
    if "account_id" in out:
        out["account_id"] = mask_account_identifier(out.get("account_id"))
    if "Account_ID" in out:
        out["Account_ID"] = mask_account_identifier(out.get("Account_ID"))
    if "receiver_account" in out:
        out["receiver_account"] = mask_account_identifier(out.get("receiver_account"))
    if "Receiver_account" in out:
        out["Receiver_account"] = mask_account_identifier(out.get("Receiver_account"))
    return out


def _mask_analytics_account_fields(data: dict) -> dict:
    """
    Ensure analytics payload never leaks raw sender/receiver account IDs,
    even when values come from stale cache entries.
    """
    out = dict(data or {})
    top_senders = out.get("top_senders") or []
    top_receivers = out.get("top_receivers") or []
    out["top_senders"] = [
        {
            **row,
            "Sender_account": mask_account_identifier(
                row.get("Sender_account") or row.get("account_id")
            ),
        }
        for row in top_senders
    ]
    out["top_receivers"] = [
        {
            **row,
            "Receiver_account": mask_account_identifier(
                row.get("Receiver_account") or row.get("account_id")
            ),
        }
        for row in top_receivers
    ]
    return out


def _coerce_row_datetime(row: dict):
    """Best-effort parse of transaction timestamp from a CSV row dict."""
    from datetime import datetime, time

    from django.utils.dateparse import parse_date, parse_datetime

    for key in ("DateTime", "datetime", "timestamp", "Timestamp", "DATE", "Date", "date"):
        if key not in row:
            continue
        v = row.get(key)
        if v is None or v == "":
            continue
        if hasattr(v, "timetuple"):
            dt = v
            if timezone.is_naive(dt):
                dt = timezone.make_aware(dt, timezone.get_current_timezone())
            return dt
        s = str(v).strip()
        dt = parse_datetime(s.replace("Z", "+00:00"))
        if dt:
            if timezone.is_naive(dt):
                dt = timezone.make_aware(dt, timezone.get_current_timezone())
            return dt
        if len(s) >= 10:
            d = parse_date(s[:10])
            if d:
                return timezone.make_aware(
                    datetime.combine(d, time.min), timezone.get_current_timezone()
                )
    return None


def _first_existing_column(frame, candidates):
    lower_to_actual = {str(column).lower(): column for column in frame.columns}
    for candidate in candidates:
        actual = lower_to_actual.get(str(candidate).lower())
        if actual is not None:
            return actual
    return None


def _coerce_datetime_series(series):
    return series.astype(str).str.strip().replace({"": None, "nan": None, "None": None})


def _add_engineered_features(frame):
    datetime_col = _first_existing_column(
        frame,
        [
            "timestamp",
            "transaction_time",
            "transaction_datetime",
            "date_time",
            "datetime",
            "DateTime",
            "created_at",
            "date",
        ],
    )
    sender_col = _first_existing_column(
        frame,
        [
            "sender_id",
            "sender_account",
            "Sender_account",
            "sender_account_id",
            "account_id",
            "customer_id",
            "user_id",
        ],
    )
    sender_country_col = _first_existing_column(
        frame,
        [
            "sender_country",
            "Sender_bank_location",
            "origin_country",
            "country_from",
        ],
    )
    receiver_country_col = _first_existing_column(
        frame,
        [
            "receiver_country",
            "Receiver_bank_location",
            "destination_country",
            "country_to",
        ],
    )
    sender_currency_col = _first_existing_column(
        frame,
        [
            "sender_currency",
            "Payment_currency",
            "source_currency",
            "currency_from",
        ],
    )
    receiver_currency_col = _first_existing_column(
        frame,
        [
            "receiver_currency",
            "Received_currency",
            "target_currency",
            "currency_to",
        ],
    )

    if datetime_col:
        dt = __import__("pandas").to_datetime(
            _coerce_datetime_series(frame[datetime_col]),
            errors="coerce",
            utc=False,
        )
        frame["hour"] = dt.dt.hour.fillna(0).astype(int)
        frame["day_of_week"] = dt.dt.dayofweek.fillna(0).astype(int)
        frame["day"] = dt.dt.day.fillna(0).astype(int)

        if sender_col:
            sort_cols = [sender_col, datetime_col]
            temp = frame.copy()
            temp["_dt"] = dt
            temp = temp.sort_values(sort_cols)
            temp["_time_diff"] = (
                temp.groupby(sender_col)["_dt"].diff().dt.total_seconds().fillna(0.0)
            )
            frame = frame.join(temp["_time_diff"]).rename(
                columns={"_time_diff": "time_diff"}
            )
        else:
            frame["time_diff"] = 0.0
    else:
        frame["hour"] = frame.get("hour", 0)
        frame["day_of_week"] = frame.get("day_of_week", 0)
        frame["day"] = frame.get("day", 0)
        frame["time_diff"] = frame.get("time_diff", 0.0)

    if sender_col:
        frame["sender_txn_count"] = frame.groupby(sender_col).cumcount() + 1
    else:
        frame["sender_txn_count"] = 1

    if sender_country_col and receiver_country_col:
        frame["cross_border"] = (
            frame[sender_country_col].astype(str).str.upper().str.strip()
            != frame[receiver_country_col].astype(str).str.upper().str.strip()
        ).astype(int)
    else:
        frame["cross_border"] = 0

    if sender_currency_col and receiver_currency_col:
        frame["currency_mismatch"] = (
            frame[sender_currency_col].astype(str).str.upper().str.strip()
            != frame[receiver_currency_col].astype(str).str.upper().str.strip()
        ).astype(int)
    else:
        frame["currency_mismatch"] = 0

    return frame


def _prepare_model_input(frame, model):
    frame = _add_engineered_features(frame)
    expected_columns = list(getattr(model, "feature_names_in_", []))
    if expected_columns:
        missing = [column for column in expected_columns if column not in frame.columns]
        for column in missing:
            frame[column] = 0
        frame = frame[expected_columns]
    return frame


def _risk_level(probability, threshold):
    low_cutoff = max(0.05, threshold * 0.7)
    high_cutoff = min(1.0, threshold + 0.2)
    critical_cutoff = min(1.0, threshold + 0.35)

    if probability < low_cutoff:
        return "Low"
    if probability < threshold:
        return "Medium"
    if probability < critical_cutoff:
        return "High"
    return "Critical"


def _rule_text(row, probability, risk_level, threshold):
    reasons = []
    amount = _to_float(row.get("amount"))
    if amount >= 10000:
        reasons.append("High amount")
    if probability >= threshold:
        reasons.append("Model score above threshold")
    if risk_level == "Critical":
        reasons.append("Critical risk band")
    return ", ".join(reasons) if reasons else "No rule triggered"


def _predict_probabilities(rows, model, preprocessor):
    try:
        import pandas as pd
    except ImportError as error:
        raise RuntimeError("pandas is required for model inference.") from error

    frame = pd.DataFrame(rows)
    transformed = None
    transform_error = None
    try:
        transformed = preprocessor.transform(frame)
    except Exception as error:
        transform_error = error

    if transformed is not None:
        probabilities = model.predict_proba(transformed)
    else:
        # Fallback: some saved models are full pipelines that accept raw DataFrame.
        try:
            prepared_frame = _prepare_model_input(frame, model)
            probabilities = model.predict_proba(prepared_frame)
        except Exception as model_error:
            raise RuntimeError(
                "Preprocessor is not fitted or incompatible, and model cannot "
                f"predict directly on raw data. Preprocessor error: {transform_error}. "
                f"Model fallback error: {model_error}. "
                "Ensure CSV contains the training features or provide a fitted preprocessor."
            ) from model_error
    if getattr(probabilities, "ndim", 1) == 2:
        return [float(item[1]) for item in probabilities]
    return [float(item) for item in probabilities]


def _to_builtin(value):
    # Make numpy / pandas scalars JSON-safe.
    if hasattr(value, "item"):
        try:
            return value.item()
        except Exception:
            pass
    if isinstance(value, dict):
        return {str(k): _to_builtin(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_builtin(v) for v in value]
    return value


def _compute_risk_levels(probabilities, threshold):
    # Vectorized-ish list comprehension; fast enough for large datasets.
    low_cutoff = max(0.05, threshold * 0.7)
    critical_cutoff = min(1.0, threshold + 0.35)
    risk_levels = []
    for p in probabilities:
        if p < low_cutoff:
            risk_levels.append("Low")
        elif p < threshold:
            risk_levels.append("Medium")
        elif p < critical_cutoff:
            risk_levels.append("High")
        else:
            risk_levels.append("Critical")
    return risk_levels


def _compute_analytics(rows, probabilities, threshold):
    try:
        import pandas as pd
    except ImportError as error:
        raise RuntimeError("pandas is required for analytics.") from error

    df = pd.DataFrame(rows)

    # Normalize key columns (case-insensitive matching).
    datetime_col = _first_existing_column(df, ["DateTime", "datetime", "timestamp", "created_at", "date"])
    sender_col = _first_existing_column(df, ["Sender_account", "sender_account", "account_id"])
    receiver_col = _first_existing_column(df, ["Receiver_account", "receiver_account"])
    amount_col = _first_existing_column(df, ["Amount", "amount"])
    sender_loc_col = _first_existing_column(df, ["Sender_bank_location", "sender_bank_location", "sender_country"])
    receiver_loc_col = _first_existing_column(df, ["Receiver_bank_location", "receiver_bank_location", "receiver_country"])
    pay_curr_col = _first_existing_column(df, ["Payment_currency", "payment_currency", "currency_from", "sender_currency"])
    recv_curr_col = _first_existing_column(df, ["Received_currency", "received_currency", "currency_to", "receiver_currency"])
    payment_type_col = _first_existing_column(df, ["Payment_type", "payment_type", "transaction_type"])

    if amount_col is None:
        df["Amount"] = 0.0
        amount_col = "Amount"
    df[amount_col] = pd.to_numeric(df[amount_col], errors="coerce").fillna(0.0)

    df["Probability"] = pd.Series(probabilities, dtype="float64")
    df["Flagged"] = df["Probability"] >= float(threshold)
    df["Risk_Level"] = pd.Series(_compute_risk_levels(probabilities, float(threshold)))

    if datetime_col is not None:
        dt = pd.to_datetime(_coerce_datetime_series(df[datetime_col]), errors="coerce", utc=False)
        df["day_of_week"] = dt.dt.dayofweek.fillna(0).astype(int)
    else:
        df["day_of_week"] = 0

    if sender_loc_col is not None and receiver_loc_col is not None:
        df["cross_border"] = (df[sender_loc_col].astype(str) != df[receiver_loc_col].astype(str)).astype(int)
    else:
        df["cross_border"] = 0

    if pay_curr_col is not None and recv_curr_col is not None:
        df["currency_mismatch"] = (df[pay_curr_col].astype(str) != df[recv_curr_col].astype(str)).astype(int)
    else:
        df["currency_mismatch"] = 0

    def dashboard_metrics(frame):
        return {
            "Total Transactions": int(len(frame)),
            "Suspicious": int(frame["Flagged"].sum()),
            "High Risk": int((frame["Risk_Level"] == "High").sum()),
            "Critical Risk": int((frame["Risk_Level"] == "Critical").sum()),
        }

    metrics = dashboard_metrics(df)
    risk_distribution = df["Risk_Level"].value_counts().to_dict()

    amount_vs_risk = df.groupby("Risk_Level")[amount_col].describe().to_dict()

    cross_border_stats = {
        "Total Cross Border": int(df["cross_border"].sum()),
        "Suspicious Cross Border": int(df.loc[df["cross_border"] == 1, "Flagged"].sum()),
        "Cross Border %": float(df["cross_border"].mean()),
    }

    top_country_pairs = []
    if sender_loc_col is not None and receiver_loc_col is not None:
        top_country_pairs = (
            df.groupby([sender_loc_col, receiver_loc_col])["Flagged"]
            .sum()
            .sort_values(ascending=False)
            .head(10)
            .reset_index()
            .rename(columns={sender_loc_col: "Sender_bank_location", receiver_loc_col: "Receiver_bank_location", "Flagged": "Flagged"})
            .to_dict(orient="records")
        )

    currency_mismatch_stats = {
        "Mismatch Count": int(df["currency_mismatch"].sum()),
        "Mismatch Suspicious": int(df.loc[df["currency_mismatch"] == 1, "Flagged"].sum()),
        "Mismatch %": float(df["currency_mismatch"].mean()),
    }

    top_senders = []
    if sender_col is not None:
        top_senders = (
            df.groupby(sender_col)["Flagged"]
            .sum()
            .sort_values(ascending=False)
            .head(10)
            .reset_index()
            .rename(columns={sender_col: "Sender_account", "Flagged": "Flagged"})
            .to_dict(orient="records")
        )
        top_senders = [
            {
                "Sender_account": mask_account_identifier(r.get("Sender_account")),
                "Flagged": int(r.get("Flagged", 0)),
            }
            for r in top_senders
        ]

    top_receivers = []
    if receiver_col is not None:
        top_receivers = (
            df.groupby(receiver_col)["Flagged"]
            .sum()
            .sort_values(ascending=False)
            .head(10)
            .reset_index()
            .rename(columns={receiver_col: "Receiver_account", "Flagged": "Flagged"})
            .to_dict(orient="records")
        )
        top_receivers = [
            {
                "Receiver_account": mask_account_identifier(r.get("Receiver_account")),
                "Flagged": int(r.get("Flagged", 0)),
            }
            for r in top_receivers
        ]

    txn_frequency = []
    if sender_col is not None:
        txn_frequency = (
            df.groupby(sender_col)
            .size()
            .sort_values(ascending=False)
            .head(10)
            .reset_index(name="Transaction_Count")
            .rename(columns={sender_col: "Sender_account"})
            .to_dict(orient="records")
        )

    suspicious_by_weekday = (
        df.loc[df["Flagged"] == True].groupby("day_of_week").size().to_dict()
    )

    # Critical transactions mapping (country / location).
    # We treat the dataset's sender bank location as "where" the critical transaction is coming from.
    critical_by_country = {}
    if sender_loc_col is not None and sender_loc_col in df.columns:
        critical_frame = df.loc[df["Risk_Level"] == "Critical", [sender_loc_col]].copy()
        # Normalize keys to keep Chart.js labels clean and stable.
        critical_frame[sender_loc_col] = (
            critical_frame[sender_loc_col].fillna("Unknown").astype(str).str.strip()
        )
        critical_counts = (
            critical_frame.groupby(sender_loc_col).size().sort_values(ascending=False).head(10)
        )
        critical_by_country = {
            str(country): int(count) for country, count in critical_counts.to_dict().items()
        }

    payment_type_risk = {}
    if payment_type_col is not None:
        payment_type_risk = (
            df.groupby(payment_type_col)["Flagged"]
            .mean()
            .sort_values(ascending=False)
            .head(20)
            .to_dict()
        )

    amount_distribution = {
        "min": float(df[amount_col].min()),
        "max": float(df[amount_col].max()),
        "mean": float(df[amount_col].mean()),
        "median": float(df[amount_col].median()),
    }

    probability_distribution = {
        "min": float(df["Probability"].min()),
        "max": float(df["Probability"].max()),
        "mean": float(df["Probability"].mean()),
        "median": float(df["Probability"].median()),
    }

    # Histograms for more visual, portfolio-level "insights".
    prob_clamped = df["Probability"].astype("float64").clip(0.0, 1.0)
    prob_bins = [i / 10.0 for i in range(0, 11)]  # 0.0-1.0 in 0.1 steps
    prob_cats = pd.cut(prob_clamped, bins=prob_bins, include_lowest=True)
    prob_counts = prob_cats.value_counts(sort=False)
    probability_histogram = {
        "labels": [str(interval).replace("(", "").replace("]", "").replace("]", "") for interval in prob_counts.index.astype(str)],
        "counts": [_to_builtin(v) for v in prob_counts.values],
    }

    amt_series = df[amount_col].astype("float64")
    amt_min = float(amt_series.min())
    amt_max = float(amt_series.max())
    if amt_min == amt_max:
        amount_histogram = {"labels": ["all"], "counts": [len(amt_series)]}
    else:
        amt_bins = 10
        amt_cats = pd.cut(amt_series, bins=amt_bins, include_lowest=True)
        amt_counts = amt_cats.value_counts(sort=False)
        amount_histogram = {
            "labels": [str(interval).replace("(", "").replace("]", "").replace("]", "") for interval in amt_counts.index.astype(str)],
            "counts": [_to_builtin(v) for v in amt_counts.values],
        }

    # Account-level index for client query widget.
    client_profiles = {}
    if sender_col is not None and sender_col in df.columns:
        sender_series = df[sender_col].fillna("").astype(str).str.strip()
        grouped = df.assign(_sender_key=sender_series).groupby("_sender_key")
        for sender_key, group in grouped:
            if not sender_key:
                continue
            payment_currencies = []
            received_currencies = []
            sender_locations = []
            receiver_locations = []
            payment_type_counts = {}

            if pay_curr_col is not None and pay_curr_col in group.columns:
                payment_currencies = sorted(
                    {str(v).strip() for v in group[pay_curr_col].fillna("").tolist() if str(v).strip()}
                )
            if recv_curr_col is not None and recv_curr_col in group.columns:
                received_currencies = sorted(
                    {str(v).strip() for v in group[recv_curr_col].fillna("").tolist() if str(v).strip()}
                )
            if sender_loc_col is not None and sender_loc_col in group.columns:
                sender_locations = [
                    str(v).strip()
                    for v in group[sender_loc_col].fillna("").tolist()
                    if str(v).strip()
                ]
            if receiver_loc_col is not None and receiver_loc_col in group.columns:
                receiver_locations = sorted(
                    {
                        str(v).strip()
                        for v in group[receiver_loc_col].fillna("").tolist()
                        if str(v).strip()
                    }
                )
            if payment_type_col is not None and payment_type_col in group.columns:
                payment_type_counts = (
                    group[payment_type_col]
                    .fillna("")
                    .astype(str)
                    .str.strip()
                    .replace("", pd.NA)
                    .dropna()
                    .value_counts()
                    .head(10)
                    .to_dict()
                )

            origin = "Unknown"
            if sender_locations:
                tmp = {}
                for loc in sender_locations:
                    tmp[loc] = tmp.get(loc, 0) + 1
                origin = max(tmp.items(), key=lambda x: x[1])[0]

            risk_dist = group["Risk_Level"].value_counts().to_dict()
            total_amt = float(group[amount_col].sum()) if amount_col in group.columns else 0.0
            avg_amt = float(group[amount_col].mean()) if amount_col in group.columns else 0.0
            max_amt = float(group[amount_col].max()) if amount_col in group.columns else 0.0

            client_profiles[sender_key] = {
                "sender_account_masked": mask_account_identifier(sender_key),
                "origin_country": origin,
                "countries_transacted_to": receiver_locations,
                "payment_currency": payment_currencies,
                "received_currency": received_currencies,
                "sender_bank_location": sorted(set(sender_locations)) if sender_locations else [],
                "receiver_bank_location": receiver_locations,
                "payment_type": [{ "type": str(k), "count": int(v)} for k, v in payment_type_counts.items()],
                "risk_distribution": {
                    "Low": int(risk_dist.get("Low", 0)),
                    "Medium": int(risk_dist.get("Medium", 0)),
                    "High": int(risk_dist.get("High", 0)),
                    "Critical": int(risk_dist.get("Critical", 0)),
                },
                "total_transactions": int(len(group)),
                "suspicious_transactions": int(group["Flagged"].sum()),
                "amount_summary": {
                    "total": round(total_amt, 2),
                    "average": round(avg_amt, 2),
                    "max": round(max_amt, 2),
                },
            }

    return _to_builtin(
        {
            "metrics": metrics,
            "risk_distribution": risk_distribution,
            "amount_vs_risk": amount_vs_risk,
            "cross_border_stats": cross_border_stats,
            "top_country_pairs": top_country_pairs,
            "currency_mismatch_stats": currency_mismatch_stats,
            "top_senders": top_senders,
            "top_receivers": top_receivers,
            "txn_frequency": txn_frequency,
            "suspicious_by_weekday": suspicious_by_weekday,
            "critical_by_country": critical_by_country,
            "payment_type_risk": payment_type_risk,
            "amount_distribution": amount_distribution,
            "probability_distribution": probability_distribution,
            "probability_histogram": probability_histogram,
            "amount_histogram": amount_histogram,
            "client_profiles": client_profiles,
        }
    )


def _detect_label_column(rows):
    if not rows:
        return None
    first = rows[0]
    for key in first.keys():
        if "is_laundering" in str(key).strip().lower():
            return key
    # fallback common names
    for key in first.keys():
        lowered = str(key).strip().lower()
        if lowered in ("label", "target", "y", "isfraud", "fraud"):
            return key
    return None


def _parse_binary_label(value):
    if value is None:
        return None
    s = str(value).strip().lower()
    if s in ("1", "true", "yes", "y", "t"):
        return 1
    if s in ("0", "false", "no", "n", "f", ""):
        return 0
    try:
        f = float(s)
        return 1 if f >= 0.5 else 0
    except (TypeError, ValueError):
        return None


def _extract_model_components(model):
    preprocessor = None
    classifier = model

    if hasattr(model, "named_steps"):
        preprocessor = model.named_steps.get("preprocessor")
        for step in model.named_steps.values():
            if hasattr(step, "predict_proba"):
                classifier = step
                break

    return preprocessor, classifier


def _get_feature_names(preprocessor):
    if preprocessor is None:
        return []
    if hasattr(preprocessor, "get_feature_names_out"):
        try:
            return list(preprocessor.get_feature_names_out())
        except Exception:
            pass
    return []


def _compute_model_feature_importance(model):
    try:
        import numpy as np
    except ImportError:
        return []

    preprocessor, classifier = _extract_model_components(model)
    feature_names = _get_feature_names(preprocessor)

    importances = None
    if hasattr(classifier, "feature_importances_"):
        importances = getattr(classifier, "feature_importances_")
    elif hasattr(classifier, "coef_"):
        coef = getattr(classifier, "coef_")
        coef_arr = np.array(coef)
        if coef_arr.ndim == 2:
            coef_vec = coef_arr[0]
        else:
            coef_vec = coef_arr
        importances = np.abs(coef_vec)

    if importances is None:
        return []

    importances = np.array(importances).reshape(-1)
    if importances.size == 0:
        return []

    top_n = 10
    top_idx = np.argsort(importances)[::-1][:top_n]
    top = []
    for idx in top_idx:
        name = feature_names[idx] if idx < len(feature_names) else f"feature_{idx}"
        top.append({"feature": str(name), "importance": float(importances[idx])})
    return top


def _compute_model_insights(rows, probabilities, threshold, model):
    try:
        import numpy as np
        import pandas as pd
        from sklearn.metrics import (
            average_precision_score,
            confusion_matrix,
            precision_recall_curve,
            roc_auc_score,
            roc_curve,
        )
    except ImportError:
        # If sklearn/pandas aren't available, return minimal response.
        return {"threshold": threshold, "error": "Required libraries missing for insights."}

    y_label_col = _detect_label_column(rows)
    y_true = None
    label_available = False
    if y_label_col is not None:
        parsed = []
        invalid = 0
        for r in rows:
            parsed_val = _parse_binary_label(r.get(y_label_col))
            if parsed_val is None:
                invalid += 1
                parsed.append(0)
            else:
                parsed.append(parsed_val)
        # If nearly all are invalid, treat as no labels.
        if len(parsed) > 0 and invalid < max(1, len(parsed) // 2):
            y_true = np.array(parsed, dtype=int)
            label_available = True

    y_prob = np.array(probabilities, dtype="float64")
    y_prob_clamped = np.clip(y_prob, 0.0, 1.0)

    insights = {
        "threshold": threshold,
        "label_column": y_label_col,
        "label_available": label_available,
        "feature_importance": _compute_model_feature_importance(model),
        "probability_histogram": None,
        "roc_auc": None,
        "pr_auc": None,
        "roc_curve": None,
        "pr_curve": None,
        "confusion_matrix": None,
        "insights_summary": [],
        "shap_image_url": None,
    }

    # Probability distribution histogram (for confidence visualization).
    prob_bins = [i / 10.0 for i in range(0, 11)]
    prob_cats = pd.cut(pd.Series(y_prob_clamped), bins=prob_bins, include_lowest=True)
    prob_counts = prob_cats.value_counts(sort=False)
    insights["probability_histogram"] = {
        "labels": [
            str(interval).replace("(", "").replace("]", "").replace("[", "").replace("]", "")
            for interval in prob_counts.index.astype(str)
        ],
        "counts": [_to_builtin(v) for v in prob_counts.values],
    }

    # ROC/PR + confusion matrix if labels are present.
    if label_available:
        y_true_metrics = y_true
        y_prob_metrics = y_prob_clamped
        used_sampling = False
        try:
            max_points = int(getattr(settings, "ML_METRICS_MAX_POINTS", 80000))
        except Exception:
            max_points = 80000
        if len(y_true) > max_points:
            # For very large uploads, sampling keeps the job responsive.
            sample_idx = np.random.choice(len(y_true), size=max_points, replace=False)
            y_true_metrics = y_true[sample_idx]
            y_prob_metrics = y_prob_clamped[sample_idx]
            used_sampling = True
        try:
            roc_auc = float(roc_auc_score(y_true_metrics, y_prob_metrics))
            fpr, tpr, _ = roc_curve(y_true_metrics, y_prob_metrics)
            pr_prec, pr_rec, _ = precision_recall_curve(y_true_metrics, y_prob_metrics)
            pr_auc = float(average_precision_score(y_true_metrics, y_prob_metrics))

            y_pred = (y_prob_metrics >= float(threshold)).astype(int)
            tn, fp, fn, tp = confusion_matrix(y_true_metrics, y_pred).ravel()

            insights["roc_auc"] = roc_auc
            insights["pr_auc"] = pr_auc
            insights["roc_curve"] = {"fpr": fpr.tolist(), "tpr": tpr.tolist()}
            insights["pr_curve"] = {
                "precision": pr_prec.tolist(),
                "recall": pr_rec.tolist(),
            }
            insights["confusion_matrix"] = {"tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)}

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

            # Top features mention.
            top_feats = insights["feature_importance"][:2]
            top_feat_text = (
                f"Top risk drivers: {top_feats[0]['feature']}"
                + (f" and {top_feats[1]['feature']}" if len(top_feats) > 1 else "")
                if top_feats
                else "Feature importance will improve once labels and fitted artifacts are available."
            )

            insights["insights_summary"] = [
                f"Model discriminative power is strong (ROC-AUC={roc_auc:.4f}).",
                f"At threshold={float(threshold):.6f}, precision={precision:.4f} and recall={recall:.4f}.",
                f"In AML, false negatives (FN={int(fn)}) are costly; this threshold aims to balance recall vs false alarms.",
                used_sampling
                    and f"Metrics were computed on a sampled subset (N={len(y_true_metrics)})."
                    or None,
                top_feat_text,
                "Threshold optimization helps align detection with investigation capacity.",
            ]
            insights["insights_summary"] = [
                x for x in insights["insights_summary"] if x is not None
            ]
        except Exception as error:
            insights["insights_summary"] = [
                "Labels were detected, but ROC/PR/confusion could not be computed due to a metric error.",
                str(error),
            ]
    else:
        insights["insights_summary"] = [
            "This upload did not include the ground-truth laundering label, so ROC/PR/confusion matrix are unavailable.",
            "Upload a labeled CSV (with `Is_laundering`) to unlock discrimination and tradeoff charts.",
        ]

    # Optional SHAP summary plot.
    if getattr(settings, "ML_ENABLE_SHAP", False):
        try:
            shap = __import__("shap")
            import matplotlib.pyplot as plt

            preprocessor, classifier = _extract_model_components(model)
            # Use fitted preprocessor if available; otherwise best-effort.
            if preprocessor is None:
                raise RuntimeError("No preprocessor found for SHAP.")

            df = pd.DataFrame(rows[:500])
            X_trans = preprocessor.transform(df)
            # TreeExplainer is typical for tree-based classifiers.
            try:
                explainer = shap.Explainer(classifier, X_trans)
                shap_values = explainer(X_trans)
            except Exception:
                explainer = shap.TreeExplainer(classifier)
                shap_values = explainer.shap_values(X_trans)

            static_dir = Path(settings.BASE_DIR) / "static" / "model_insights"
            static_dir.mkdir(parents=True, exist_ok=True)
            out_path = static_dir / "shap_summary.png"
            plt.figure()
            shap.summary_plot(shap_values, show=False)
            plt.tight_layout()
            plt.savefig(out_path, dpi=160)
            insights["shap_image_url"] = "/static/model_insights/shap_summary.png"
        except Exception:
            insights["shap_image_url"] = None

    insights = _to_builtin(insights)

    # Persist latest insights JSON for portfolio/debugging.
    try:
        static_dir = Path(settings.BASE_DIR) / "static" / "model_insights"
        static_dir.mkdir(parents=True, exist_ok=True)
        (static_dir / "latest_insights.json").write_text(
            json.dumps(insights, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass

    return insights


def _build_analysis_response(rows, probabilities, threshold):
    max_alert_rows = int(getattr(settings, "ML_MAX_ALERT_ROWS", 2000))
    max_alert_rows = max(100, min(max_alert_rows, 10000))
    alerts = []
    suspicious = 0
    high_risk = 0
    critical_risk = 0
    low_risk = 0
    medium_risk = 0
    for row, probability in zip(rows, probabilities):
        risk_level = _risk_level(probability, threshold)
        flagged = probability >= threshold
        if risk_level == "Low":
            low_risk += 1
        elif risk_level == "Medium":
            medium_risk += 1
        if flagged:
            suspicious += 1
            if len(alerts) < max_alert_rows:
                account_id = _row_value(row, ["Sender_account", "account_id"]) or ""
                receiver = str(
                    _row_value(row, ["Receiver_account", "receiver_account"]) or ""
                ).strip()[:64]
                payment_currency = str(
                    _row_value(
                        row,
                        [
                            "Payment_currency",
                            "payment_currency",
                            "currency_from",
                            "sender_currency",
                            "Payment Currency",
                        ],
                    )
                    or ""
                ).strip()[:32]
                received_currency = str(
                    _row_value(
                        row,
                        [
                            "Received_currency",
                            "received_currency",
                            "currency_to",
                            "receiver_currency",
                            "Received Currency",
                        ],
                    )
                    or ""
                ).strip()[:32]
                sender_bank_location = str(
                    _row_value(
                        row,
                        [
                            "Sender_bank_location",
                            "sender_bank_location",
                            "sender_country",
                            "Sender Bank Location",
                        ],
                    )
                    or ""
                ).strip()[:64]
                receiver_bank_location = str(
                    _row_value(
                        row,
                        [
                            "Receiver_bank_location",
                            "receiver_bank_location",
                            "receiver_country",
                            "Receiver Bank Location",
                        ],
                    )
                    or ""
                ).strip()[:64]
                payment_type = str(
                    _row_value(
                        row,
                        [
                            "Payment_type",
                            "payment_type",
                            "transaction_type",
                            "Payment Type",
                        ],
                    )
                    or ""
                ).strip()[:64]
                amount = _to_float(_row_value(row, ["Amount", "amount"]))
                txn_dt = _coerce_row_datetime(row)
                alerts.append(
                    {
                        "Probability": round(probability, 4),
                        "Risk_Level": risk_level,
                        "Rules": _rule_text(row, probability, risk_level, threshold),
                        "Flagged": True,
                        "Alert": "Potential Money Laundering",
                        "Case_Status": "Open",
                        "Account_ID": account_id,
                        "Receiver_account": receiver,
                        "Payment_currency": payment_currency,
                        "Received_currency": received_currency,
                        "Sender_bank_location": sender_bank_location,
                        "Receiver_bank_location": receiver_bank_location,
                        "Payment_type": payment_type,
                        "Amount": amount,
                        "Txn_Timestamp": txn_dt.isoformat() if txn_dt else None,
                    }
                )
        if risk_level == "High":
            high_risk += 1
        if risk_level == "Critical":
            critical_risk += 1

    return {
        "threshold": threshold,
        "metrics": {
            "Total Transactions": len(rows),
            "Suspicious": suspicious,
            "High Risk": high_risk,
            "Critical Risk": critical_risk,
        },
        "risk_distribution": {
            "Low": low_risk,
            "Medium": medium_risk,
            "High": high_risk,
            "Critical": critical_risk,
        },
        "alerts": alerts,
        "alerts_total": suspicious,
        "alerts_shown": len(alerts),
        "alerts_truncated": suspicious > len(alerts),
    }


def _build_case_rows(rows, probabilities, threshold):
    """
    Build persistence payload for AlertCase using all scored rows
    (not only flagged rows), so monitoring/case pages can use full dataset scale.
    """
    out = []
    for row, probability in zip(rows, probabilities):
        risk_level = _risk_level(probability, threshold)
        flagged = probability >= threshold
        account_id = _row_value(row, ["Sender_account", "account_id"]) or ""
        receiver = str(
            _row_value(row, ["Receiver_account", "receiver_account"]) or ""
        ).strip()[:64]
        payment_currency = str(
            _row_value(
                row,
                [
                    "Payment_currency",
                    "payment_currency",
                    "currency_from",
                    "sender_currency",
                    "Payment Currency",
                ],
            )
            or ""
        ).strip()[:32]
        received_currency = str(
            _row_value(
                row,
                [
                    "Received_currency",
                    "received_currency",
                    "currency_to",
                    "receiver_currency",
                    "Received Currency",
                ],
            )
            or ""
        ).strip()[:32]
        sender_bank_location = str(
            _row_value(
                row,
                [
                    "Sender_bank_location",
                    "sender_bank_location",
                    "sender_country",
                    "Sender Bank Location",
                ],
            )
            or ""
        ).strip()[:64]
        receiver_bank_location = str(
            _row_value(
                row,
                [
                    "Receiver_bank_location",
                    "receiver_bank_location",
                    "receiver_country",
                    "Receiver Bank Location",
                ],
            )
            or ""
        ).strip()[:64]
        payment_type = str(
            _row_value(
                row,
                [
                    "Payment_type",
                    "payment_type",
                    "transaction_type",
                    "Payment Type",
                ],
            )
            or ""
        ).strip()[:64]
        amount = _to_float(_row_value(row, ["Amount", "amount"]))
        txn_dt = _coerce_row_datetime(row)
        out.append(
            {
                "Probability": round(probability, 4),
                "Risk_Level": risk_level,
                "Rules": _rule_text(row, probability, risk_level, threshold),
                "Flagged": bool(flagged),
                "Alert": "Potential Money Laundering" if flagged else "Monitor",
                "Case_Status": "Open",
                "Account_ID": account_id,
                "Receiver_account": receiver,
                "Payment_currency": payment_currency,
                "Received_currency": received_currency,
                "Sender_bank_location": sender_bank_location,
                "Receiver_bank_location": receiver_bank_location,
                "Payment_type": payment_type,
                "Amount": amount,
                "Txn_Timestamp": txn_dt.isoformat() if txn_dt else None,
            }
        )
    return out


def _update_job(job_id, **fields):
    with _ANALYSIS_JOBS_LOCK:
        job = _ANALYSIS_JOBS.get(job_id)
        if not job:
            return
        job.update(fields)


def _run_analysis_job(job_id, file_bytes):
    try:
        _update_job(job_id, status="processing", progress=10, message="Parsing CSV...")
        file_like = io.BytesIO(file_bytes)
        file_like.name = "uploaded.csv"
        rows = _parse_csv(file_like)

        _update_job(job_id, progress=40, message="Loading model artifacts...")
        model, preprocessor, threshold = _load_artifacts()

        _update_job(job_id, progress=70, message="Running model predictions...")
        probabilities = _predict_probabilities(rows, model, preprocessor)
        if len(probabilities) != len(rows):
            raise RuntimeError("Model output does not match input row count.")

        _update_job(job_id, progress=85, message="Computing analytics...")
        analytics = _compute_analytics(rows, probabilities, threshold)
        cache.set(_CACHE_LATEST_ANALYTICS_KEY, analytics, _CACHE_TIMEOUT_SECONDS)

        _update_job(job_id, progress=90, message="Computing risk metrics...")
        result = _build_analysis_response(rows, probabilities, threshold)
        cache_payload = {
            "job_id": job_id,
            "completed_at": timezone.now().isoformat(),
            "result": result,
        }
        cache.set(_CACHE_LATEST_ANALYSIS_KEY, cache_payload, _CACHE_TIMEOUT_SECONDS)
        cache.set(f"{_CACHE_LATEST_ANALYSIS_KEY}:{job_id}", cache_payload, _CACHE_TIMEOUT_SECONDS)
        try:
            _persist_alert_cases(
                _build_case_rows(rows, probabilities, threshold), source="upload"
            )
        except Exception:
            # Don't fail the analysis job if DB persistence fails; UI can use cached results.
            pass
        _update_job(
            job_id,
            status="completed",
            progress=100,
            message="Analysis complete.",
            result=result,
        )
    except (ValueError, FileNotFoundError, RuntimeError) as error:
        _update_job(job_id, status="failed", message=str(error), error=str(error))
    except Exception as error:
        message = f"Prediction failed: {error.__class__.__name__}: {error}"
        _update_job(job_id, status="failed", message=message, error=message)


@require_POST
def analyze_transactions_submit(request):
    uploaded_file = request.FILES.get("file")
    if uploaded_file is None:
        return JsonResponse({"error": "Please upload a CSV file."}, status=400)

    job_id = uuid.uuid4().hex
    with _ANALYSIS_JOBS_LOCK:
        _ANALYSIS_JOBS[job_id] = {
            "status": "queued",
            "progress": 0,
            "message": "Queued for processing...",
            "result": None,
            "error": None,
        }

    worker = threading.Thread(
        target=_run_analysis_job,
        args=(job_id, uploaded_file.read()),
        daemon=True,
    )
    worker.start()

    return JsonResponse({"job_id": job_id, "status": "queued"}, status=202)


def analyze_transactions_status(request, job_id):
    with _ANALYSIS_JOBS_LOCK:
        job = _ANALYSIS_JOBS.get(job_id)
        if not job:
            return JsonResponse({"error": "Job not found."}, status=404)
        payload = {
            "job_id": job_id,
            "status": job["status"],
            "progress": job["progress"],
            "message": job["message"],
        }
        if job["status"] == "completed":
            payload["result"] = job["result"]
        if job["status"] == "failed":
            payload["error"] = job["error"]
    return JsonResponse(payload)


@require_GET
def analytics_data(request):
    # Strict DB-first analytics (no cache dependency).
    try:
        max_rows = int(getattr(settings, "AML_ANALYTICS_DB_MAX_ROWS", 500000))
        max_rows = max(1000, min(max_rows, 1000000))
        qs = AlertCase.objects.order_by("-created_at")[:max_rows]
        if qs:
            rows = []
            probabilities = []
            for case in qs:
                rows.append(
                    {
                        "DateTime": (
                            (case.txn_timestamp or case.created_at).isoformat()
                            if (case.txn_timestamp or case.created_at)
                            else ""
                        ),
                        "Sender_account": case.account_id or "",
                        "Receiver_account": case.receiver_account or "",
                        "Amount": float(case.amount) if case.amount is not None else 0.0,
                        "Sender_bank_location": case.sender_bank_location
                        or case.country
                        or "",
                        "Receiver_bank_location": case.receiver_bank_location or "",
                        "Payment_currency": case.payment_currency or "",
                        "Received_currency": case.received_currency or "",
                        "Payment_type": case.payment_type or "",
                    }
                )
                probabilities.append(float(case.probability or 0.0))

            # Resolve threshold from DB/app settings for risk bucket parity.
            raw_threshold = (
                AppSetting.objects.filter(key="optimal_threshold")
                .values_list("value", flat=True)
                .first()
            )
            try:
                threshold = float(raw_threshold) if raw_threshold is not None else 0.5
            except (ValueError, TypeError):
                threshold = 0.5

            data = _compute_analytics(rows, probabilities, threshold)
            # Align total metric to full Transaction table size when available.
            try:
                tx_total = Transaction.objects.count()
                if tx_total and isinstance(data, dict):
                    metrics = dict(data.get("metrics") or {})
                    metrics["Total Transactions"] = int(tx_total)
                    data["metrics"] = metrics
            except Exception:
                pass
            return JsonResponse(_mask_analytics_account_fields(data))
    except OperationalError:
        pass
    # Final fallback: provide DB transaction totals even without AlertCase rows.
    try:
        tx_total = Transaction.objects.count()
        if tx_total:
            return JsonResponse(
                {
                    "metrics": {
                        "Total Transactions": int(tx_total),
                        "Suspicious": 0,
                        "High Risk": 0,
                        "Critical Risk": 0,
                    },
                    "risk_distribution": {"Low": 0, "Medium": 0, "High": 0, "Critical": 0},
                    "amount_vs_risk": {},
                    "cross_border_stats": {},
                    "top_country_pairs": [],
                    "currency_mismatch_stats": {},
                    "top_senders": [],
                    "top_receivers": [],
                    "txn_frequency": [],
                    "suspicious_by_weekday": {},
                    "critical_by_country": {},
                    "amount_distribution": {},
                    "amount_histogram": {"labels": [], "counts": []},
                    "partial": True,
                    "warning": "Risk analytics require AlertCase scoring rows; totals are from Transaction table.",
                }
            )
    except OperationalError:
        pass
    return JsonResponse({"error": "No database analytics available yet."}, status=404)


@require_GET
def model_insights_data(request):
    data = cache.get(_CACHE_LATEST_MODEL_INSIGHTS_KEY)
    if not data:
        return JsonResponse(
            {"error": "No uploaded dataset model insights available yet."}, status=404
        )
    return JsonResponse(data)


def _persist_alert_cases(alert_rows, source="upload", write_audit_log=True):
    if not alert_rows:
        return
    max_persist = int(getattr(settings, "AML_MAX_CASE_PERSIST_ROWS", 500000))
    max_persist = max(1000, min(max_persist, 1000000))
    # Ensure pages reflect the latest uploaded dataset (latest-run wins).
    AlertCase.objects.filter(source=source).delete()
    cases = []
    from django.utils.dateparse import parse_datetime

    def _auto_assignment_pool():
        """
        Pick eligible users for auto-assignment.
        - If AML_AUTO_ASSIGN_USER_ID / AML_AUTO_ASSIGN_USER_IDS is provided, use that pool.
        - Otherwise, assign across all users in the COMPLIANCE_OFFICER_GROUP (round-robin).
        """
        User = get_user_model()
        ids = []

        single = str(getattr(settings, "AML_AUTO_ASSIGN_USER_ID", "") or "").strip()
        if single:
            try:
                ids = [int(single)]
            except ValueError:
                ids = []

        ids_str = str(getattr(settings, "AML_AUTO_ASSIGN_USER_IDS", "") or "").strip()
        if not ids and ids_str:
            try:
                ids = [int(x.strip()) for x in ids_str.split(",") if x.strip()]
            except ValueError:
                ids = []

        if ids:
            return list(User.objects.filter(id__in=ids, is_active=True).order_by("id"))

        # Default: Compliance Officers group pool.
        try:
            return list(
                User.objects.filter(is_active=True, groups__name=COMPLIANCE_OFFICER_GROUP)
                .order_by("id")
                .distinct()
            )
        except Exception:
            return []

    assignees = _auto_assignment_pool()
    assignee_count = len(assignees)

    for idx, item in enumerate(alert_rows[:max_persist]):
        amount = item.get("Amount")
        ts_raw = item.get("Txn_Timestamp")
        parsed_ts = None
        if ts_raw:
            if isinstance(ts_raw, str):
                parsed_ts = parse_datetime(ts_raw.replace("Z", "+00:00"))
            elif hasattr(ts_raw, "timetuple"):
                parsed_ts = ts_raw
            if parsed_ts and timezone.is_naive(parsed_ts):
                parsed_ts = timezone.make_aware(
                    parsed_ts, timezone.get_current_timezone()
                )
        assigned_user = assignees[idx % assignee_count] if assignee_count else None
        assigned_to = assigned_user.get_username() if assigned_user else ""

        cases.append(
            AlertCase(
                probability=item["Probability"],
                risk_level=item["Risk_Level"],
                rules=item["Rules"],
                flagged=bool(item.get("Flagged", False)),
                alert=item["Alert"],
                case_status=AlertCase.STATUS_UNDER_REVIEW,
                account_id=str(item.get("Account_ID", "")),
                receiver_account=str(item.get("Receiver_account", "") or "")[:64],
                payment_currency=str(item.get("Payment_currency", "") or "")[:32],
                received_currency=str(item.get("Received_currency", "") or "")[:32],
                sender_bank_location=str(item.get("Sender_bank_location", "") or "")[:64],
                receiver_bank_location=str(item.get("Receiver_bank_location", "") or "")[:64],
                payment_type=str(item.get("Payment_type", "") or "")[:64],
                amount=amount if amount is not None else None,
                txn_timestamp=parsed_ts,
                assigned_user=assigned_user,
                assigned_to=assigned_to,
                source=source,
            )
        )
    AlertCase.objects.bulk_create(cases, batch_size=1000)
    if write_audit_log:
        AuditLog.objects.create(
            action="ALERTS_GENERATED",
            details=f"Created {len(cases)} alert cases from {source} analysis.",
        )


@require_GET
def dashboard_data(request):
    cached = cache.get(_CACHE_LATEST_ANALYSIS_KEY)
    if cached and cached.get("result"):
        result = cached["result"]
        metrics = result.get("metrics", {})
        risk_distribution = result.get("risk_distribution", {})
        completed_at = cached.get("completed_at") or ""
        day = completed_at.split("T")[0] if "T" in completed_at else None
        tx_over_time = []
        if day:
            tx_over_time = [{"d": day, "count": metrics.get("Total Transactions", 0)}]
        return JsonResponse(
            {
                "metrics": metrics,
                "risk_distribution": risk_distribution,
                "transactions_over_time": tx_over_time,
            }
        )

    try:
        total = AlertCase.objects.count()
        suspicious = AlertCase.objects.filter(flagged=True).count()
        high = AlertCase.objects.filter(risk_level="High").count()
        critical = AlertCase.objects.filter(risk_level="Critical").count()

        risk_distribution = {
            "Low": AlertCase.objects.filter(risk_level="Low").count(),
            "Medium": AlertCase.objects.filter(risk_level="Medium").count(),
            "High": high,
            "Critical": critical,
        }
        tx_over_time = list(
            AlertCase.objects.annotate(d=TruncDate("created_at"))
            .values("d")
            .annotate(count=Count("id"))
            .order_by("d")[:30]
        )
        return JsonResponse(
            {
                "metrics": {
                    "Total Transactions": total,
                    "Suspicious": suspicious,
                    "High Risk": high,
                    "Critical Risk": critical,
                },
                "risk_distribution": risk_distribution,
                "transactions_over_time": tx_over_time,
            }
        )
    except OperationalError:
        return JsonResponse(
            {
                "metrics": {
                    "Total Transactions": 0,
                    "Suspicious": 0,
                    "High Risk": 0,
                    "Critical Risk": 0,
                },
                "risk_distribution": {"Low": 0, "Medium": 0, "High": 0, "Critical": 0},
                "transactions_over_time": [],
            }
        )


@require_GET
def client_insights_data(request):
    """
    Client-level query endpoint for dashboard search:
    - profile summary (counts, risk mix, amount stats)
    - counterparties and countries
    - trend analytics by day
    """
    account_query = str(request.GET.get("account", "")).strip()
    if not account_query:
        return JsonResponse({"error": "account query is required"}, status=400)

    try:
        qs = AlertCase.objects.filter(account_id__icontains=account_query).order_by("-created_at")
        if not qs.exists():
            dataset_snapshot = _load_dataset_client_snapshot(account_query)
            if dataset_snapshot:
                return JsonResponse(
                    {
                        "found": True,
                        "account_query": mask_account_identifier(account_query),
                        **dataset_snapshot,
                        "notes": [
                            "Client details loaded from dataset file because no AlertCase rows were found.",
                        ],
                    }
                )
            return JsonResponse(
                {
                    "account_query": mask_account_identifier(account_query),
                    "found": False,
                    "message": "No client cases found for this account in database or dataset.",
                },
                status=404,
            )

        total_cases = qs.count()
        suspicious = qs.filter(flagged=True).count()
        risk_distribution = {
            "Low": qs.filter(risk_level="Low").count(),
            "Medium": qs.filter(risk_level="Medium").count(),
            "High": qs.filter(risk_level="High").count(),
            "Critical": qs.filter(risk_level="Critical").count(),
        }

        amounts = [float(v.amount) for v in qs if v.amount is not None]
        amount_summary = {
            "total": round(sum(amounts), 2) if amounts else 0.0,
            "average": round((sum(amounts) / len(amounts)), 2) if amounts else 0.0,
            "max": round(max(amounts), 2) if amounts else 0.0,
        }

        sender_locs = [str(v.sender_bank_location or "").strip() for v in qs if str(v.sender_bank_location or "").strip()]
        receiver_locs = sorted({str(v.receiver_bank_location or "").strip() for v in qs if str(v.receiver_bank_location or "").strip()})
        payment_currency = sorted({str(v.payment_currency or "").strip() for v in qs if str(v.payment_currency or "").strip()})
        received_currency = sorted({str(v.received_currency or "").strip() for v in qs if str(v.received_currency or "").strip()})

        payment_type_counts = {}
        for row in qs:
            ptype = str(row.payment_type or "").strip()
            if not ptype:
                continue
            payment_type_counts[ptype] = payment_type_counts.get(ptype, 0) + 1
        payment_type = [
            {"type": k, "count": v}
            for k, v in sorted(payment_type_counts.items(), key=lambda x: x[1], reverse=True)
        ]

        sender_loc_counts = {}
        for loc in sender_locs:
            sender_loc_counts[loc] = sender_loc_counts.get(loc, 0) + 1
        origin_country = (
            max(sender_loc_counts.items(), key=lambda x: x[1])[0] if sender_loc_counts else "Unknown"
        )
        countries_transacted_to = receiver_locs

        # Fallback for legacy records that were saved before new DB fields existed.
        if (
            not payment_currency
            and not received_currency
            and not sender_locs
            and not receiver_locs
            and not payment_type
        ):
            analytics = cache.get(_CACHE_LATEST_ANALYTICS_KEY) or {}
            profiles = analytics.get("client_profiles", {}) if isinstance(analytics, dict) else {}
            profile = profiles.get(account_query)
            if not profile:
                for k, v in profiles.items():
                    if account_query.lower() in str(k).lower():
                        profile = v
                        break
            if profile:
                payment_currency = profile.get("payment_currency", []) or []
                received_currency = profile.get("received_currency", []) or []
                sender_locs = profile.get("sender_bank_location", []) or []
                receiver_locs = profile.get("receiver_bank_location", []) or []
                payment_type = profile.get("payment_type", []) or []
                origin_country = str(profile.get("origin_country") or origin_country)
                countries_transacted_to = profile.get("countries_transacted_to", []) or receiver_locs
            else:
                # Final fallback: read dataset directly and backfill DB for this client.
                dataset_fields = _load_customer_fields_from_dataset(account_query)
                if dataset_fields:
                    payment_currency = dataset_fields.get("payment_currency", []) or []
                    received_currency = dataset_fields.get("received_currency", []) or []
                    sender_locs = dataset_fields.get("sender_bank_location", []) or []
                    receiver_locs = dataset_fields.get("receiver_bank_location", []) or []
                    payment_type = dataset_fields.get("payment_type", []) or []

                    if sender_locs:
                        sender_loc_counts = {}
                        for loc in sender_locs:
                            sender_loc_counts[loc] = sender_loc_counts.get(loc, 0) + 1
                        origin_country = max(sender_loc_counts.items(), key=lambda x: x[1])[0]
                    countries_transacted_to = receiver_locs

                    # Persist representative values so subsequent requests read directly from DB.
                    if payment_currency:
                        qs.filter(payment_currency="").update(payment_currency=payment_currency[0][:32])
                    if received_currency:
                        qs.filter(received_currency="").update(received_currency=received_currency[0][:32])
                    if sender_locs:
                        qs.filter(sender_bank_location="").update(sender_bank_location=sender_locs[0][:64])
                    if receiver_locs:
                        qs.filter(receiver_bank_location="").update(receiver_bank_location=receiver_locs[0][:64])
                    if payment_type:
                        top_type = str(payment_type[0].get("type") or "").strip()
                        if top_type:
                            qs.filter(payment_type="").update(payment_type=top_type[:64])

        counterparties_count = {}
        for r in qs:
            counter = str(r.receiver_account or "").strip()
            if not counter:
                continue
            counterparties_count[counter] = counterparties_count.get(counter, 0) + 1
        top_counterparties = [
            {"receiver_account": mask_account_identifier(k), "count": v}
            for k, v in sorted(counterparties_count.items(), key=lambda x: x[1], reverse=True)[:10]
        ]

        by_day = {}
        for row in qs[:5000]:
            d = (row.txn_timestamp or row.created_at)
            day = d.date().isoformat() if d else "Unknown"
            by_day[day] = by_day.get(day, 0) + 1
        trend = [{"d": k, "count": by_day[k]} for k in sorted(by_day.keys()) if k != "Unknown"]

        recent = []
        for row in qs[:100]:
            recent.append(
                {
                    "id": row.id,
                    "sender_account": mask_account_identifier(row.account_id),
                    "receiver_account": mask_account_identifier(row.receiver_account),
                    "amount": float(row.amount) if row.amount is not None else None,
                    "country": row.country or "Unknown",
                    "risk_level": row.risk_level,
                    "probability": row.probability,
                    "status": row.case_status,
                    "timestamp": (row.txn_timestamp or row.created_at).isoformat()
                    if (row.txn_timestamp or row.created_at)
                    else "",
                }
            )

        return JsonResponse(
            {
                "found": True,
                "account_query": mask_account_identifier(account_query),
                "summary": {
                    "total_cases": total_cases,
                    "suspicious_cases": suspicious,
                    "origin_country": origin_country,
                    "countries_transacted_to": countries_transacted_to,
                    "amount_summary": amount_summary,
                },
                "customer_fields": {
                    "payment_currency": payment_currency,
                    "received_currency": received_currency,
                    "sender_bank_location": sorted(set(sender_locs)),
                    "receiver_bank_location": receiver_locs,
                    "payment_type": payment_type,
                    "matched_account": mask_account_identifier(account_query),
                },
                "risk_distribution": risk_distribution,
                "trend_by_day": trend,
                "top_counterparties": top_counterparties,
                "recent_transactions": recent,
                "notes": [
                    "Origin country is derived from Sender_bank_location.",
                    "Customer fields are sourced from AlertCase records in the database.",
                ],
            }
        )
    except OperationalError:
        return JsonResponse({"error": "Database not ready yet."}, status=503)


@require_GET
def alerts_data(request):
    risk = request.GET.get("risk")
    status = request.GET.get("status")
    try:
        upload_cases_exist = AlertCase.objects.filter(source="upload").exists()
        dataset_cases_exist = AlertCase.objects.filter(source=_DATASET_SOURCE).exists()
    except OperationalError:
        upload_cases_exist = False
        dataset_cases_exist = False

    if upload_cases_exist or dataset_cases_exist:
        qs = AlertCase.objects.filter(
            source="upload" if upload_cases_exist else _DATASET_SOURCE
        )
        if risk:
            qs = qs.filter(risk_level=risk)
        if status:
            qs = qs.filter(case_status=status)
        items = list(
            qs.values(
                "id",
                "probability",
                "risk_level",
                "rules",
                "flagged",
                "alert",
                "case_status",
                "assigned_to",
                "account_id",
                "receiver_account",
                "amount",
                "investigation_notes",
                "txn_timestamp",
                "created_at",
            )[:2000]
        )
        items = [_mask_alert_payload_accounts(i) for i in items]
        return JsonResponse({"count": len(items), "items": items})

    cached = cache.get(_CACHE_LATEST_ANALYSIS_KEY)
    if not cached or not cached.get("result"):
        return JsonResponse({"count": 0, "items": []})

    result = cached["result"]
    alerts = result.get("alerts", [])

    def _map_case_status(case_status):
        if not case_status:
            return AlertCase.STATUS_UNDER_REVIEW
        normalized = str(case_status).strip().upper()
        mapping = {
            "OPEN": AlertCase.STATUS_UNDER_REVIEW,
            "UNDER_REVIEW": AlertCase.STATUS_UNDER_REVIEW,
            "UNDER REVIEW": AlertCase.STATUS_UNDER_REVIEW,
            "CONFIRMED": AlertCase.STATUS_CONFIRMED,
            "CONFIRMED SUSPICIOUS": AlertCase.STATUS_CONFIRMED,
            "FALSE_POSITIVE": AlertCase.STATUS_FALSE_POSITIVE,
            "FALSE POSITIVE": AlertCase.STATUS_FALSE_POSITIVE,
            "ESCALATED": AlertCase.STATUS_ESCALATED,
            "RESOLVED": AlertCase.STATUS_RESOLVED,
        }
        return mapping.get(normalized, AlertCase.STATUS_UNDER_REVIEW)

    filtered = []
    for alert in alerts:
        risk_level = alert.get("Risk_Level")
        case_status_val = _map_case_status(alert.get("Case_Status"))

        if risk and risk_level != risk:
            continue
        if status and case_status_val != status:
            continue

        filtered.append(
            {
                "id": -1,
                "probability": alert.get("Probability"),
                "risk_level": risk_level,
                "rules": alert.get("Rules"),
                "flagged": True,
                "alert": alert.get("Alert"),
                "case_status": case_status_val,
                "assigned_to": "",
                "account_id": alert.get("Account_ID", ""),
                "receiver_account": alert.get("Receiver_account", ""),
                "amount": alert.get("Amount"),
                "investigation_notes": "",
                "txn_timestamp": alert.get("Txn_Timestamp"),
                "created_at": cached.get("completed_at", ""),
            }
        )
        if len(filtered) >= 2000:
            break

    filtered = [_mask_alert_payload_accounts(i) for i in filtered]
    return JsonResponse({"count": len(filtered), "items": filtered})


@require_POST
def alert_action(request, alert_id):
    case = AlertCase.objects.filter(id=alert_id).first()
    if not case:
        return JsonResponse({"error": "Alert case not found."}, status=404)
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except Exception:
        payload = {}
    action = payload.get("action", "").strip().lower()
    assignee = str(payload.get("assigned_to", "")).strip()
    if action == "approve":
        case.case_status = AlertCase.STATUS_CONFIRMED
    elif action == "reject":
        case.case_status = AlertCase.STATUS_FALSE_POSITIVE
    elif action == "review":
        case.case_status = AlertCase.STATUS_UNDER_REVIEW
    elif action == "escalate":
        case.case_status = AlertCase.STATUS_ESCALATED
    elif action == "resolve":
        case.case_status = AlertCase.STATUS_RESOLVED
    if assignee:
        case.assigned_to = assignee
    case.save(update_fields=["case_status", "assigned_to", "updated_at"])
    AuditLog.objects.create(
        action="ALERT_ACTION",
        details=f"Case {case.id} updated to {case.case_status}, assignee={case.assigned_to}.",
    )
    return JsonResponse({"ok": True})


@require_GET
def cases_data(request):
    try:
        upload_cases_exist = AlertCase.objects.filter(source="upload").exists()
        dataset_cases_exist = AlertCase.objects.filter(source=_DATASET_SOURCE).exists()
    except OperationalError:
        upload_cases_exist = False
        dataset_cases_exist = False

    if upload_cases_exist or dataset_cases_exist:
        qs = AlertCase.objects.filter(
            source="upload" if upload_cases_exist else _DATASET_SOURCE
        )
        paginator = Paginator(qs, 100)
        page = int(request.GET.get("page", "1"))
        current = paginator.get_page(page)
        data = list(
            current.object_list.values(
                "id",
                "account_id",
                "amount",
                "risk_level",
                "case_status",
                "assigned_to",
            )
        )
        data = [_mask_alert_payload_accounts(i) for i in data]
        return JsonResponse(
            {"page": current.number, "pages": paginator.num_pages, "items": data}
        )

    cached = cache.get(_CACHE_LATEST_ANALYSIS_KEY)
    if not cached or not cached.get("result"):
        return JsonResponse({"page": 1, "pages": 1, "items": []})

    result = cached["result"]
    alerts = result.get("alerts", [])
    page = int(request.GET.get("page", "1"))
    page_size = 100
    start = (page - 1) * page_size
    end = start + page_size

    def _map_case_status(case_status):
        normalized = str(case_status).strip().upper() if case_status else ""
        if normalized in ("OPEN", "UNDER_REVIEW", "UNDER REVIEW", ""):
            return AlertCase.STATUS_UNDER_REVIEW
        if normalized in ("CONFIRMED", "CONFIRMED SUSPICIOUS"):
            return AlertCase.STATUS_CONFIRMED
        if normalized in ("FALSE_POSITIVE", "FALSE POSITIVE"):
            return AlertCase.STATUS_FALSE_POSITIVE
        if normalized == "ESCALATED":
            return AlertCase.STATUS_ESCALATED
        if normalized == "RESOLVED":
            return AlertCase.STATUS_RESOLVED
        return AlertCase.STATUS_UNDER_REVIEW

    items = []
    for alert in alerts[start:end]:
        items.append(
            {
                "id": -1,
                "account_id": alert.get("Account_ID", ""),
                "amount": alert.get("Amount"),
                "risk_level": alert.get("Risk_Level"),
                "case_status": _map_case_status(alert.get("Case_Status")),
                "assigned_to": "",
            }
        )

    items = [_mask_alert_payload_accounts(i) for i in items]
    return JsonResponse({"page": page, "pages": 1, "items": items})


@require_GET
def explorer_data(request):
    try:
        upload_cases_exist = AlertCase.objects.filter(source="upload").exists()
        dataset_cases_exist = AlertCase.objects.filter(source=_DATASET_SOURCE).exists()
    except OperationalError:
        upload_cases_exist = False
        dataset_cases_exist = False

    qs = (
        AlertCase.objects.filter(source="upload")
        if upload_cases_exist
        else (
            AlertCase.objects.filter(source=_DATASET_SOURCE)
            if dataset_cases_exist
            else None
        )
    )

    account = request.GET.get("account", "").strip()
    risk = request.GET.get("risk", "").strip()
    country = request.GET.get("country", "").strip()
    date_from = request.GET.get("date_from", "").strip()
    date_to = request.GET.get("date_to", "").strip()
    min_amount = request.GET.get("min_amount", "").strip()
    max_amount = request.GET.get("max_amount", "").strip()

    if qs is not None:
        if account:
            qs = qs.filter(account_id__icontains=account)
        if risk:
            qs = qs.filter(risk_level=risk)
        if country:
            qs = qs.filter(country__icontains=country)
        if date_from:
            qs = qs.filter(created_at__date__gte=date_from)
        if date_to:
            qs = qs.filter(created_at__date__lte=date_to)
        if min_amount:
            try:
                qs = qs.filter(amount__gte=float(min_amount))
            except ValueError:
                pass
        if max_amount:
            try:
                qs = qs.filter(amount__lte=float(max_amount))
            except ValueError:
                pass

        items = list(
            qs.values(
                "id",
                "account_id",
                "amount",
                "risk_level",
                "country",
                "case_status",
                "created_at",
            )[:2000]
        )
        items = [_mask_alert_payload_accounts(i) for i in items]
        return JsonResponse({"count": len(items), "items": items})

    cached = cache.get(_CACHE_LATEST_ANALYSIS_KEY)
    if not cached or not cached.get("result"):
        return JsonResponse({"count": 0, "items": []})

    result = cached["result"]
    alerts = result.get("alerts", [])
    completed_at = cached.get("completed_at", "")
    completed_day = completed_at.split("T")[0] if "T" in completed_at else ""

    def _in_date_range():
        if date_from and completed_day < date_from:
            return False
        if date_to and completed_day > date_to:
            return False
        return True

    if country:
        # Cache fallback doesn't store country for now.
        return JsonResponse({"count": 0, "items": []})

    if not _in_date_range():
        return JsonResponse({"count": 0, "items": []})

    filtered = []
    for alert in alerts:
        if account and (alert.get("Account_ID", "") or "").find(account) == -1:
            continue
        if risk and alert.get("Risk_Level") != risk:
            continue
        amount = alert.get("Amount")
        try:
            amount_val = float(amount) if amount is not None else None
        except (TypeError, ValueError):
            amount_val = None
        if min_amount:
            try:
                if amount_val is None or amount_val < float(min_amount):
                    continue
            except ValueError:
                pass
        if max_amount:
            try:
                if amount_val is None or amount_val > float(max_amount):
                    continue
            except ValueError:
                pass

        filtered.append(
            {
                "id": -1,
                "account_id": alert.get("Account_ID", ""),
                "amount": alert.get("Amount"),
                "risk_level": alert.get("Risk_Level"),
                "country": "",
                "case_status": AlertCase.STATUS_UNDER_REVIEW,
                "created_at": completed_at,
            }
        )
        if len(filtered) >= 2000:
            break

    filtered = [_mask_alert_payload_accounts(i) for i in filtered]
    return JsonResponse({"count": len(filtered), "items": filtered})


@csrf_exempt
def settings_data(request):
    if request.method == "GET":
        value = AppSetting.objects.filter(key="optimal_threshold").values_list(
            "value", flat=True
        ).first() or str(getattr(settings, "ML_OPTIMAL_THRESHOLD", 0.603939))
        return JsonResponse({"optimal_threshold": float(value)})
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)
    if not user_is_aml_admin(request.user):
        return JsonResponse(
            {"error": "AML Admin role required to update the threshold."},
            status=403,
        )
    payload = json.loads(request.body.decode("utf-8"))
    value = payload.get("optimal_threshold")
    if value is None:
        return JsonResponse({"error": "optimal_threshold is required"}, status=400)
    AppSetting.objects.update_or_create(
        key="optimal_threshold", defaults={"value": str(float(value))}
    )
    AuditLog.objects.create(
        action="SETTINGS_UPDATED", details=f"optimal_threshold set to {value}"
    )
    return JsonResponse({"ok": True})


@require_GET
def audit_logs_data(request):
    items = list(AuditLog.objects.values("action", "details", "actor", "created_at")[:500])
    return JsonResponse({"count": len(items), "items": items})


@csrf_exempt
def chat_ask(request):
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        payload = json.loads(request.body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        payload = {}
    message = str(payload.get("message", "")).strip()
    if not message:
        return JsonResponse({"error": "message is required"}, status=400)

    ensure_aml_dataset_ready()
    response = answer_question(message)

    try:
        AuditLog.objects.create(
            action="CHAT_ASK",
            details=f"Q: {message[:500]} | A: {str(response.get('answer', ''))[:500]}",
            actor="user",
        )
    except Exception:
        pass

    return JsonResponse(response)


@csrf_exempt
def transactions(request):
    if request.method == "GET":
        items = [_transaction_to_dict(tx) for tx in Transaction.objects.all()[:100]]
        return JsonResponse({"count": len(items), "transactions": items})

    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        payload = json.loads(request.body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JsonResponse({"error": "Invalid JSON payload"}, status=400)

    account_id = str(payload.get("account_id", "")).strip()
    if not account_id:
        return JsonResponse({"error": "account_id is required"}, status=400)

    try:
        amount = Decimal(str(payload.get("amount", "")))
    except (InvalidOperation, ValueError):
        return JsonResponse({"error": "amount must be a valid number"}, status=400)

    currency = str(payload.get("currency", "USD")).upper().strip()[:8] or "USD"
    transaction_type = str(payload.get("transaction_type", "transfer")).strip()[:32]
    description = str(payload.get("description", "")).strip()

    suspicious_reason = _get_suspicious_reason(account_id, amount)
    transaction = Transaction.objects.create(
        account_id=account_id,
        amount=amount,
        currency=currency,
        transaction_type=transaction_type or "transfer",
        description=description,
        is_suspicious=bool(suspicious_reason),
        suspicious_reason=suspicious_reason,
    )
    return JsonResponse(_transaction_to_dict(transaction), status=201)


def alerts(request):
    if request.method != "GET":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    items = [
        _transaction_to_dict(tx)
        for tx in Transaction.objects.filter(is_suspicious=True)[:100]
    ]
    return JsonResponse({"count": len(items), "alerts": items})
