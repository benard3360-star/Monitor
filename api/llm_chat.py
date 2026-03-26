from __future__ import annotations

import json
import logging
from typing import Any, Optional

from django.conf import settings

logger = logging.getLogger(__name__)


def _kb_context_json(kb: Any) -> str:
    payload = {
        "preferred_data_source": kb.preferred_source,
        "analysis_completed_at": kb.dataset_completed_at,
        "ml_optimal_threshold": kb.threshold,
        "metrics": kb.metrics,
        "risk_distribution": kb.risk_distribution,
        "top_senders_flagged": kb.top_senders[:10],
        "top_receivers_flagged": kb.top_receivers[:10],
        "case_status_counts": kb.status_counts,
        "recent_audit_log": [
            {
                "action": row["action"],
                "details": (row.get("details") or "")[:240],
                "created_at": str(row.get("created_at", "")),
            }
            for row in kb.recent_audit[:12]
        ],
    }
    return json.dumps(payload, indent=2, default=str)


def try_openai_chat_reply(user_message: str, kb: Any) -> Optional[str]:
    """
    Returns assistant text from OpenAI when configured, or None to fall back to heuristics.
    """
    api_key = getattr(settings, "OPENAI_API_KEY", "") or ""
    api_key = str(api_key).strip()
    if not api_key:
        return None

    try:
        from openai import OpenAI
    except ImportError:
        logger.warning("OpenAI chat skipped: install the `openai` package (pip install openai).")
        return None

    model = getattr(settings, "OPENAI_CHAT_MODEL", "gpt-4o-mini") or "gpt-4o-mini"
    model = str(model).strip() or "gpt-4o-mini"

    context = _kb_context_json(kb)
    system = (
        "You are an AML (anti–money laundering) assistant for a transaction monitoring dashboard.\n"
        "Answer the user's question using ONLY the facts in the JSON context below. "
        "If the context does not contain enough information, say so clearly and suggest they check "
        "Analytics, Alerts, Cases, or ensure the dataset has been ingested — do not invent numbers, "
        "account IDs, or thresholds.\n"
        "Be concise, accurate, and professional.\n\n"
        "=== WORKSPACE CONTEXT (JSON) ===\n"
        f"{context}"
    )

    try:
        client = OpenAI(api_key=api_key)
        completion = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user_message},
            ],
            max_tokens=int(getattr(settings, "OPENAI_CHAT_MAX_TOKENS", 900)),
            temperature=float(getattr(settings, "OPENAI_CHAT_TEMPERATURE", 0.25)),
        )
        choice = completion.choices[0] if completion.choices else None
        text = (choice.message.content or "").strip() if choice and choice.message else ""
        return text or None
    except Exception as exc:
        logger.warning("OpenAI chat request failed: %s", exc)
        return None
