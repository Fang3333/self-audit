"""密码泄露检测：HaveIBeenPwned Pwned Passwords，k-anonymity 模型。

原理：只把 SHA1 前 5 位发出去，服务端返回该前缀下所有后 35 位 + 泄露次数，
本地做匹配。明文密码和完整哈希都不离开本机。
接口免费、无需 key，实测可用。
"""

from __future__ import annotations

import hashlib
import math
import re

from . import net

API = "https://api.pwnedpasswords.com/range/{prefix}"

# 最常见的弱口令，用于本地快速告警（不联网也能判）
COMMON = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "abc123",
    "1234567890", "iloveyou", "000000", "qwerty123", "1q2w3e",
    "admin", "letmein", "monkey", "welcome", "88888888", "666666",
    "a123456", "123qwe", "zxcvbnm", "asdfgh", "qazwsx", "1qaz2wsx",
    "woaini", "5201314", "1314520", "wang123", "li123456", "zhang123",
}


def strength(pw: str) -> dict:
    """粗评估：组合空间熵 + 常见模式识别。

    纯熵会高估 password123 这种（字符集够宽、长度够），所以常见模式单独扣分。
    """
    n = len(pw)
    pool = 0
    if re.search(r"[a-z]", pw):
        pool += 26
    if re.search(r"[A-Z]", pw):
        pool += 26
    if re.search(r"\d", pw):
        pool += 10
    if re.search(r"[^\w]", pw):
        pool += 32
    if re.search(r"[\u4e00-\u9fff]", pw):
        pool += 2000

    entropy = round(n * math.log2(pool)) if pool else 0

    lower = pw.lower()
    reasons: list[str] = []

    # 常见模式：这些直接压到「弱」，不管熵多少
    if lower in COMMON:
        reasons.append("常见弱口令")
    if re.fullmatch(r"\d+", pw):
        reasons.append("纯数字")
    if re.fullmatch(r"[a-zA-Z]+", pw):
        reasons.append("纯字母")
    if re.fullmatch(r"(.)\1+", pw):
        reasons.append("单字符重复")
    # 常见词根 + 纯数字后缀（password123 / admin2024）
    if re.fullmatch(r"[a-z]{4,}\d{1,6}", lower) and re.search(
            r"(pass|admin|root|test|user|qwer|abc|love|wang|zhang|li|liu)", lower):
        reasons.append("词根+数字")
    # 键盘序列
    if re.search(r"(qwer|asdf|zxcv|1234|4321|0987)", lower):
        reasons.append("键盘序列")

    if reasons:
        level = "弱（" + "、".join(reasons) + "）"
    elif n < 8:
        level = "弱（长度不足 8 位）"
    elif entropy < 36:
        level = "弱"
    elif entropy < 55:
        level = "中"
    elif entropy < 75:
        level = "强"
    else:
        level = "很强"

    return {
        "length": n,
        "charset": pool,
        "entropy_bits": entropy,
        "level": level,
        "is_common": bool(reasons),
    }


def check(pw: str) -> dict:
    """返回该密码在已知泄露库中出现的次数。0 表示未发现（不等于绝对安全）。"""
    if not pw:
        return {"pwned": None, "count": 0, "error": "empty password"}

    sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    status, body, _ = net.request(API.format(prefix=prefix), timeout=15)
    if status != 200:
        return {"pwned": None, "count": 0, "error": f"HTTP {status}"}

    count = 0
    for line in body.decode("utf-8", "ignore").splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0] == suffix:
            try:
                count = int(parts[1])
            except ValueError:
                count = 0
            break

    return {
        "pwned": count > 0,
        "count": count,
        "hash_prefix": prefix,
        "strength": strength(pw),
    }


def check_many(passwords: list[str]) -> list[dict]:
    out = []
    for pw in passwords:
        r = check(pw)
        r["masked"] = (pw[0] + "*" * max(1, len(pw) - 2) + pw[-1]) if len(pw) > 2 else "**"
        out.append(r)
    return out
