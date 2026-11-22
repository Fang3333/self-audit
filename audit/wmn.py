"""B 级检测：WhatsMyName 社区维护的站点规则。

判定依据是「HTTP 状态码 + 页面特征串」，规则由社区校准，但存在两类必然误报：
1. 站点改版后 e_string / m_string 失效；
2. 规则是用它的测试账号校准的，换个用户名不一定成立。

所以 B 级结果一律标 needs_review，报告里单独一栏，不并入 A 级的确定结论。

规则文件不随仓库分发（上游数据由 WhatsMyName 维护，vendored 进来越久越失真），
首次运行时按需下载到本地缓存。
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import net

_RULES: list[dict] | None = None
_HOME = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_RULE_PATH = os.path.join(_HOME, "wmn-data.json")

# 上游最近一次更新超过这个天数就重新拉；0 表示每次都检查
MAX_AGE_DAYS = 30

_UPSTREAM = [
    "https://cdn.jsdelivr.net/gh/WebBreacher/WhatsMyName@main/wmn-data.json",
    "https://fastly.jsdelivr.net/gh/WebBreacher/WhatsMyName@main/wmn-data.json",
    "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json",
]


class RulesUnavailable(RuntimeError):
    """规则文件缺失且下载失败。"""


def _stale(path: str) -> bool:
    if not os.path.exists(path):
        return True
    if MAX_AGE_DAYS <= 0:
        return True
    age = (time.time() - os.path.getmtime(path)) / 86400
    return age > MAX_AGE_DAYS


def fetch_rules(path: str | None = None, force: bool = False) -> str:
    """确保本地有规则文件。返回文件路径。"""
    p = path or _RULE_PATH
    if not force and not _stale(p):
        return p

    errors = []
    for url in _UPSTREAM:
        status, body, _ = net.request(url, timeout=30, retries=0)
        if status != 200 or len(body) < 50_000:
            errors.append(f"{url.split('/')[2]}: HTTP {status} / {len(body)}B")
            continue
        try:
            data = json.loads(body.decode("utf-8"))
        except Exception as e:
            errors.append(f"{url.split('/')[2]}: JSON 解析失败 {e}")
            continue
        if not data.get("sites"):
            errors.append(f"{url.split('/')[2]}: 内容为空")
            continue
        tmp = p + ".tmp"
        with open(tmp, "wb") as f:
            f.write(body)
        os.replace(tmp, p)
        return p

    # 下载全失败，但本地还有旧文件就先用着
    if os.path.exists(p):
        return p
    raise RulesUnavailable(
        "规则文件不存在且下载失败：\n  " + "\n  ".join(errors) +
        "\n\n手动放一份到 " + p + " 后重试。"
    )


def load_rules(path: str | None = None, auto_fetch: bool = True) -> list[dict]:
    global _RULES
    if _RULES is not None and path is None:
        return _RULES
    p = path or (_RULE_PATH if not auto_fetch else fetch_rules(path))
    with open(p, encoding="utf-8") as f:
        data = json.load(f)
    rules = [s for s in data.get("sites", []) if s.get("uri_check")]
    if path is None:
        _RULES = rules
    return rules


def _judge(rule: dict, status: int, body: bytes) -> str:
    """返回 exists / absent / unknown。"""
    if status == 0:
        return "unknown"
    text = body.decode("utf-8", "ignore")

    e_code = rule.get("e_code")
    e_str = rule.get("e_string")
    m_code = rule.get("m_code")
    m_str = rule.get("m_string")

    # 明确的「不存在」优先判定：有些站点对不存在的用户返回 200 + 错误文案
    if m_str and m_str in text:
        return "absent"
    if m_code is not None and status == m_code and not (e_str and e_str in text):
        return "absent"

    if e_str:
        if status == e_code and e_str in text:
            return "exists"
        return "unknown" if status not in (m_code,) else "absent"

    # 没给 e_string 的规则只能看状态码，置信度更低
    if status == e_code:
        return "exists"
    return "absent" if status == m_code else "unknown"


def check_one(rule: dict, username: str) -> dict:
    acct = username
    for ch in rule.get("strip_bad_char") or "":
        acct = acct.replace(ch, "")
    url = rule["uri_check"].replace("{account}", urllib.parse.quote(acct))

    headers = dict(rule.get("headers") or {})
    method = "GET"
    data = None
    if rule.get("post_body"):
        method = "POST"
        data = rule["post_body"].replace("{account}", urllib.parse.quote(acct)).encode()
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    status, body, _ = net.request(url, method=method, data=data, headers=headers,
                                  timeout=6, retries=0)
    verdict = _judge(rule, status, body)
    return {
        "name": rule.get("name"),
        "url": rule.get("uri_pretty", rule["uri_check"]).replace("{account}", acct),
        "cat": rule.get("cat", "other"),
        "status": verdict,
        "http": status,
        "has_estring": bool(rule.get("e_string")),
        "tier": "B",
    }


def verify_hit(item: dict, username: str) -> str:
    """命中项二次验证：页面里到底有没有出现这个用户名。

    WMN 规则只看状态码和特征串，站点改版后容易把 200 的通用页当成账号页。
    这里再看一眼正文，命中用户名的记 confirmed，否则记 suspicious，
    报告里分开列，避免把误报当结论。
    """
    if not item.get("url"):
        return "suspicious"
    status, body, _ = net.request(item["url"], timeout=6, retries=0)
    if status == 0:
        return "suspicious"
    text = body.decode("utf-8", "ignore").lower()
    u = username.lower()
    if u in text:
        return "confirmed"
    # 有些站把用户名写成带空格/下划线的形式
    for sep in (" ", "_", "-", "%20"):
        if u.replace(" ", sep) in text:
            return "confirmed"
    return "suspicious"


def scan(username: str, categories: list[str] | None = None,
         workers: int = 20, limit: int | None = None,
         verify: bool = True) -> dict:
    rules = load_rules()
    if categories:
        want = {c.lower() for c in categories}
        rules = [r for r in rules if (r.get("cat") or "").lower() in want]
    if limit:
        rules = rules[:limit]

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(check_one, r, username): r for r in rules}
        for fu in as_completed(futs):
            try:
                results.append(fu.result())
            except Exception as e:
                results.append({
                    "name": futs[fu].get("name"),
                    "url": "",
                    "cat": futs[fu].get("cat", "other"),
                    "status": "unknown",
                    "http": 0,
                    "error": str(e)[:60],
                    "tier": "B",
                })

    # 对命中项做二次验证
    hits = [r for r in results if r["status"] == "exists"]
    if verify and hits:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs2 = {pool.submit(verify_hit, h, username): h for h in hits}
            for fu in as_completed(futs2):
                h = futs2[fu]
                try:
                    h["confidence"] = fu.result()
                except Exception:
                    h["confidence"] = "suspicious"

    for r in results:
        if r["status"] == "exists" and "confidence" not in r:
            r["confidence"] = "unverified"

    stat = {"exists": 0, "absent": 0, "unknown": 0, "confirmed": 0}
    for r in results:
        stat[r["status"]] = stat.get(r["status"], 0) + 1
        if r.get("confidence") == "confirmed":
            stat["confirmed"] += 1

    # 有账号的按分类排，方便看聚集在哪个领域
    results.sort(key=lambda r: (r["status"] != "exists",
                                r.get("confidence") != "confirmed",
                                r["cat"], r["name"] or ""))
    return {"username": username, "total": len(rules), "stats": stat, "results": results}


def categories() -> dict[str, int]:
    out: dict[str, int] = {}
    for r in load_rules():
        c = r.get("cat", "other")
        out[c] = out.get(c, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))
