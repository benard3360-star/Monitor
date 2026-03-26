from __future__ import annotations


def mask_account_identifier(value: object) -> str:
    """
    Mask the middle 4 characters of account-like identifiers.
    Example: 12345678 -> 12####78, 40485329 -> 40####29
    """
    s = str(value or "").strip()
    if not s:
        return ""
    if len(s) <= 4:
        return "#" * len(s)
    if len(s) <= 6:
        return s[0] + "####" + s[-1]
    start = (len(s) - 4) // 2
    end = start + 4
    return f"{s[:start]}####{s[end:]}"

