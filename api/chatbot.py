from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from django.conf import settings
from django.core.cache import cache

from .models import AlertCase, AppSetting, AuditLog
from .security_utils import mask_account_identifier

_CACHE_TIMEOUT_SECONDS = int(getattr(settings, "ML_CACHE_TIMEOUT_SECONDS", 3600))
_CACHE_LATEST_ANALYSIS_KEY = "aml:latest_analysis_result"
_CACHE_LATEST_ANALYTICS_KEY = "aml:latest_analysis_analytics"


@dataclass
class ChatKB:
    preferred_source: Optional[str]
    dataset_completed_at: str
    threshold: float
    metrics: Dict[str, Any]
    risk_distribution: Dict[str, Any]
    top_senders: list[dict]
    top_receivers: list[dict]
    status_counts: Dict[str, int]
    recent_audit: list[dict]


def _get_threshold() -> float:
    db_threshold = (
        AppSetting.objects.filter(key="optimal_threshold").values_list("value", flat=True).first()
    )
    if db_threshold is not None:
        try:
            return float(db_threshold)
        except (TypeError, ValueError):
            pass
    return float(getattr(settings, "ML_OPTIMAL_THRESHOLD", 0.603939))


def _preferred_source() -> Optional[str]:
    # If dataset ingest exists, prefer it over upload.
    try:
        if AlertCase.objects.filter(source="dataset").exists():
            return "dataset"
        if AlertCase.objects.filter(source="upload").exists():
            return "upload"
    except Exception:
        pass
    return None


def _load_latest_cache_payload() -> tuple[dict, dict]:
    analysis = cache.get(_CACHE_LATEST_ANALYSIS_KEY)
    analytics = cache.get(_CACHE_LATEST_ANALYTICS_KEY)
    return (analysis or {}), (analytics or {})


def build_chat_kb() -> ChatKB:
    cached = cache.get("aml:chat_kb_v1")
    if cached:
        return cached

    preferred = _preferred_source()
    threshold = _get_threshold()
    analysis_cache, analytics_cache = _load_latest_cache_payload()

    dataset_completed_at = ""
    result = {}
    if isinstance(analysis_cache, dict):
        dataset_completed_at = analysis_cache.get("completed_at", "") or ""
        result = analysis_cache.get("result", {}) or {}

    metrics = result.get("metrics", {}) or {}
    risk_distribution = result.get("risk_distribution", {}) or {}

    if not risk_distribution:
        # fallback to DB
        try:
            if preferred:
                risk_distribution = {
                    "Low": AlertCase.objects.filter(source=preferred, risk_level="Low").count(),
                    "Medium": AlertCase.objects.filter(source=preferred, risk_level="Medium").count(),
                    "High": AlertCase.objects.filter(source=preferred, risk_level="High").count(),
                    "Critical": AlertCase.objects.filter(source=preferred, risk_level="Critical").count(),
                }
        except Exception:
            risk_distribution = {}

    # Top tables: prefer analytics cache, else compute senders from DB.
    analytics = analytics_cache or {}
    top_senders = analytics.get("top_senders", []) or []
    top_receivers = analytics.get("top_receivers", []) or []
    if not top_senders and preferred:
        try:
            from django.db.models import Count

            top_senders = list(
                AlertCase.objects.filter(source=preferred)
                .values("account_id")
                .annotate(flagged=Count("id"))
                .order_by("-flagged")[:10]
            )
            # normalize keys to match analytics structure
            top_senders = [
                {"Sender_account": mask_account_identifier(row["account_id"]), "Flagged": row["flagged"]}
                for row in top_senders
            ]
        except Exception:
            top_senders = []

    # Case status counts from DB (most reliable).
    status_counts = {
        "UNDER_REVIEW": 0,
        "CONFIRMED": 0,
        "FALSE_POSITIVE": 0,
        "ESCALATED": 0,
        "RESOLVED": 0,
    }
    if preferred:
        try:
            status_counts = {
                "UNDER_REVIEW": AlertCase.objects.filter(source=preferred, case_status="UNDER_REVIEW").count(),
                "CONFIRMED": AlertCase.objects.filter(source=preferred, case_status="CONFIRMED").count(),
                "FALSE_POSITIVE": AlertCase.objects.filter(source=preferred, case_status="FALSE_POSITIVE").count(),
                "ESCALATED": AlertCase.objects.filter(source=preferred, case_status="ESCALATED").count(),
                "RESOLVED": AlertCase.objects.filter(source=preferred, case_status="RESOLVED").count(),
            }
        except Exception:
            pass

    recent_audit = []
    try:
        recent_audit = list(
            AuditLog.objects.values("action", "details", "created_at").order_by("-created_at")[:10]
        )
    except Exception:
        recent_audit = []

    kb = ChatKB(
        preferred_source=preferred,
        dataset_completed_at=dataset_completed_at,
        threshold=threshold,
        metrics=metrics,
        risk_distribution=risk_distribution,
        top_senders=top_senders,
        top_receivers=top_receivers,
        status_counts=status_counts,
        recent_audit=recent_audit,
    )

    cache.set("aml:chat_kb_v1", kb, _CACHE_TIMEOUT_SECONDS)
    return kb


def _format_int(x: Any) -> str:
    try:
        return f"{int(x):,}"
    except Exception:
        return str(x)


def answer_question(message: str) -> Dict[str, Any]:
    kb = build_chat_kb()
    raw = (message or "").strip()
    if not raw:
        return {"answer": "Please type a question.", "sources": {}}

    if getattr(settings, "OPENAI_API_KEY", "").strip():
        from .llm_chat import try_openai_chat_reply

        openai_text = try_openai_chat_reply(raw, kb)
        if openai_text:
            return {
                "answer": openai_text,
                "sources": {
                    "provider": "openai",
                    "model": getattr(settings, "OPENAI_CHAT_MODEL", "gpt-4o-mini"),
                },
            }

    return answer_question_heuristic(kb, raw.lower())


def answer_question_heuristic(kb: ChatKB, msg: str) -> Dict[str, Any]:
    threshold = kb.threshold

    if any(
        p in msg
        for p in (
            "what can you",
            "what do you",
            "help me",
            "how do i use",
            "capabilities",
        )
    ):
        return {
            "answer": (
                "I answer from your latest ingested data and caches. Try:\n"
                "• Threshold — “What is the current threshold?”\n"
                "• Volumes — “How many suspicious transactions?” or “Total transactions?”\n"
                "• Accounts — “Top risky senders?” / “Top risky receivers?”\n"
                "• Cases — “Case status breakdown?”\n"
                "• Audit — “Recent audit actions?”"
            ),
            "sources": {},
        }

    # "Why" follow-ups should be handled before generic "top sender/receiver" handlers
    # so we don't just repeat the ranked list.
    if (
        any(p in msg for p in ("why", "reason", "explain"))
        and "top" in msg
        and ("sender" in msg or "senders" in msg)
    ):
        if not kb.top_senders:
            return {
                "answer": "I can’t explain yet because top senders aren’t available. Run dataset ingest so analytics are populated.",
                "sources": {},
            }
        top = kb.top_senders[:5]
        lines = [
            f"{i+1}. {mask_account_identifier(row.get('Sender_account') or row.get('account_id') or '-')} — {row.get('Flagged') or 0} flagged case(s)"
            for i, row in enumerate(top)
        ]
        return {
            "answer": (
                "Why these accounts are the top risky senders:\n"
                "They’re ranked by the number of flagged (risky) cases for each sender in the latest dataset.\n\n"
                "Top senders by flagged case count:\n"
                + "\n".join(lines)
            ),
            "sources": {"top_senders": top},
        }

    if (
        any(p in msg for p in ("why", "reason", "explain"))
        and "top" in msg
        and ("receiver" in msg or "receivers" in msg)
    ):
        if not kb.top_receivers:
            return {
                "answer": "I can’t explain yet because top receivers aren’t available. Run dataset ingest so analytics are populated.",
                "sources": {},
            }
        top = kb.top_receivers[:5]
        lines = [
            f"{i+1}. {mask_account_identifier(row.get('Receiver_account') or row.get('account_id') or '-')} — {row.get('Flagged') or 0} flagged case(s)"
            for i, row in enumerate(top)
        ]
        return {
            "answer": (
                "Why these accounts are the top risky receivers:\n"
                "They’re ranked by the number of flagged (risky) cases for each receiver in the latest dataset.\n\n"
                "Top receivers by flagged case count:\n"
                + "\n".join(lines)
            ),
            "sources": {"top_receivers": top},
        }

    if "threshold" in msg or "optimal" in msg:
        return {
            "answer": (
                f"The current ML optimal threshold is {threshold:.6f}. "
                "Transactions with predicted probability >= this value are classified into higher risk bands."
            ),
            "sources": {"threshold": threshold, "source": kb.preferred_source},
        }

    if "total" in msg and ("transaction" in msg or "transactions" in msg):
        total = kb.metrics.get("Total Transactions")
        suspicious = kb.metrics.get("Suspicious")
        high = kb.metrics.get("High Risk")
        critical = kb.metrics.get("Critical Risk")
        if total is None:
            return {
                "answer": "Total Transactions is not available. Run dataset ingest or ensure cache is populated.",
                "sources": {"warning": "missing_total_transactions"},
            }
        return {
            "answer": (
                "Latest AML dataset totals:\n"
                f"1) Total transactions: {_format_int(total)}\n"
                f"2) Suspicious: {_format_int(suspicious)}\n"
                f"3) High risk: {_format_int(high)}\n"
                f"4) Critical risk: {_format_int(critical)}\n"
                f"\nThreshold used: {threshold:.6f}\n"
                "\nNext step — ask: “Top risky senders?” or “Case status breakdown?”"
            ),
            "sources": {"threshold": threshold, "metrics": kb.metrics},
        }

    if "suspicious" in msg and ("count" in msg or "how many" in msg or "number" in msg):
        suspicious = kb.metrics.get("Suspicious")
        if suspicious is None:
            suspicious = 0
        return {
            "answer": f"Suspicious transactions (latest dataset) = {_format_int(suspicious)}.",
            "sources": {"suspicious": suspicious, "threshold": threshold},
        }

    if "high risk" in msg and "count" in msg:
        high = kb.metrics.get("High Risk") or 0
        return {
            "answer": f"High Risk transactions (latest dataset) = {_format_int(high)}.",
            "sources": {"high_risk": high},
        }

    if "critical" in msg and ("count" in msg or "transactions" in msg):
        critical = kb.metrics.get("Critical Risk") or 0
        return {
            "answer": f"Critical Risk transactions (latest dataset) = {_format_int(critical)}.",
            "sources": {"critical_risk": critical},
        }

    if "top" in msg and ("sender" in msg or "senders" in msg):
        if kb.top_senders:
            top = kb.top_senders[:5]
            lines = [
                f"{i+1}. {mask_account_identifier(row.get('Sender_account') or row.get('account_id') or '-')} — {row.get('Flagged') or 0} flagged case(s)"
                for i, row in enumerate(top)
            ]
            return {
                "answer": (
                    "Top risky senders (ranked by flagged case count):\n" + "\n".join(lines)
                    + "\n\nWant the reason? Ask: “why are they top risky senders?”"
                ),
                "sources": {"top_senders": top},
            }
        return {"answer": "I can’t find top senders yet. Run dataset ingest so analytics cache is populated.", "sources": {}}

    if "top" in msg and ("receiver" in msg or "receivers" in msg):
        if kb.top_receivers:
            top = kb.top_receivers[:5]
            lines = [
                f"{i+1}. {mask_account_identifier(row.get('Receiver_account') or row.get('account_id') or '-')} — {row.get('Flagged') or 0} flagged case(s)"
                for i, row in enumerate(top)
            ]
            return {
                "answer": (
                    "Top risky receivers (ranked by flagged case count):\n" + "\n".join(lines)
                    + "\n\nWant the reason? Ask: “why are they top risky receivers?”"
                ),
                "sources": {"top_receivers": top},
            }
        return {"answer": "I can’t find top receivers yet. Run dataset ingest so analytics cache is populated.", "sources": {}}

    if (
        "under review" in msg
        or "false positive" in msg
        or "confirmed" in msg
        or ("case" in msg and ("status" in msg or "breakdown" in msg or "cases" in msg))
    ):
        return {
            "answer": (
                "Case status breakdown:\n"
                f"- Under Review: {_format_int(kb.status_counts.get('UNDER_REVIEW', 0))}\n"
                f"- Confirmed Suspicious: {_format_int(kb.status_counts.get('CONFIRMED', 0))}\n"
                f"- False Positive: {_format_int(kb.status_counts.get('FALSE_POSITIVE', 0))}\n"
                f"- Escalated: {_format_int(kb.status_counts.get('ESCALATED', 0))}"
                    f"\n- Resolved: {_format_int(kb.status_counts.get('RESOLVED', 0))}"
            ),
            "sources": {"status_counts": kb.status_counts},
        }

    if "risk" in msg and ("distribution" in msg or "breakdown" in msg or "split" in msg):
        rd = kb.risk_distribution or {}
        if not rd:
            return {
                "answer": "Risk distribution isn’t available yet. Run dataset ingest or open Analytics after a successful run.",
                "sources": {},
            }
        lines = [f"- {k}: {_format_int(v)}" for k, v in sorted(rd.items(), key=lambda x: str(x[0]))]
        return {
            "answer": "Risk level counts (latest data):\n" + "\n".join(lines),
            "sources": {"risk_distribution": rd},
        }

    if "audit" in msg or "recent" in msg or "actions" in msg:
        items = kb.recent_audit[:5]
        if not items:
            return {"answer": "No audit log entries available yet.", "sources": {}}
        lines = [f"- {it['created_at']}: {it['action']} ({it.get('details','')[:80]})" for it in items]
        return {"answer": "Recent audit events:\n" + "\n".join(lines), "sources": {"recent": items}}

    # Default response: summarize the latest dataset.
    total = kb.metrics.get("Total Transactions")
    suspicious = kb.metrics.get("Suspicious")
    high = kb.metrics.get("High Risk")
    critical = kb.metrics.get("Critical Risk")
    return {
        "answer": (
            "Latest AML dataset snapshot:\n"
            f"1) Threshold: {threshold:.6f}\n"
            f"2) Total transactions: {_format_int(total) if total is not None else 'N/A'}\n"
            f"3) Suspicious: {_format_int(suspicious) if suspicious is not None else 'N/A'}\n"
            f"4) High risk: {_format_int(high) if high is not None else 'N/A'}\n"
            f"5) Critical risk: {_format_int(critical) if critical is not None else 'N/A'}\n\n"
            "Next step — pick one:\n"
            "- Why are the top risky senders high risk?\n"
            "- Top risky receivers?\n"
            "- Case status breakdown?\n"
            "- Recent audit actions?"
        ),
        "sources": {"metrics": kb.metrics, "threshold": threshold, "preferred_source": kb.preferred_source},
    }
