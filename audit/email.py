"""邮箱档案：服务商识别 + 域名 MX 验证 + 一次性邮箱判定 + 公开暴露搜索。

能自动给的：语法、服务商、域名是否真能收信、是否临时邮箱、公开网页提及。
拿不到的：这个邮箱注册过哪些站（没有公开接口），以及 HIBP 泄露记录
（需要付费 API key，工具只给查询链接）。

Gravatar 和 DNS-over-HTTPS 在国内直连不通，实测过，所以 MX 走系统 nslookup。
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from urllib.parse import quote

from . import net

# ── 服务商识别 ──────────────────────────────────────────
PROVIDERS: dict[str, tuple[str, str]] = {}


def _p(names: list[str], provider: str, kind: str) -> None:
    for n in names:
        PROVIDERS[n] = (provider, kind)


_p(["qq.com", "foxmail.com", "vip.qq.com"], "腾讯 QQ 邮箱", "国内主流")
_p(["163.com", "126.com", "yeah.net", "188.com"], "网易邮箱", "国内主流")
_p(["sina.com", "sina.cn", "sohu.com", "139.com", "189.cn", "wo.cn"], "运营商/门户邮箱", "国内主流")
_p(["aliyun.com", "aliyun.cn"], "阿里云邮箱", "企业/自建")
_p(["gmail.com", "googlemail.com"], "Gmail", "境外")
_p(["outlook.com", "hotmail.com", "live.com", "msn.com"], "Outlook / Hotmail", "境外")
_p(["icloud.com", "me.com", "mac.com"], "iCloud", "境外")
_p(["protonmail.com", "proton.me", "pm.me"], "Proton Mail", "境外(加密)")
_p(["yahoo.com", "ymail.com", "yahoo.co.jp"], "Yahoo", "境外")

# 一次性 / 临时邮箱（这类域名收信即焚，注册用它们通常是为了躲追溯）
DISPOSABLE = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "temp-mail.org",
    "throwawaymail.com", "yopmail.com", "sharklasers.com", "getnada.com",
    "maildrop.cc", "dispostable.com", "trashmail.com", "tempail.com",
    "moakt.com", "emailondeck.com", "burnermail.io", "mohmal.com",
    "inboxkitten.com", "mailnesia.com", "discard.email", "spamgourmet.com",
    "mytemp.email", "tempmail.com", "fakeinbox.com", "mailcatch.com",
    "grr.la", "guerrillamailblock.com", "pokemail.net", "spambox.us",
}

_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_MX_WIN = re.compile(r"MX preference\s*=\s*(\d+),\s*mail exchanger\s*=\s*(\S+)")
_MX_UNIX = re.compile(r"mail exchanger\s*=\s*(\d+)\s+(\S+?)\.?$", re.M)


def normalize(raw: str) -> str:
    s = raw.strip().strip("<>").strip()
    if s.lower().startswith("mailto:"):
        s = s[7:]
    return s.lower()


def is_valid(email: str) -> bool:
    return bool(_RE.match(email)) and len(email) <= 254


def lookup_provider(domain: str) -> tuple[str, str]:
    d = domain.lower()
    if d in PROVIDERS:
        return PROVIDERS[d]
    if d.endswith(".edu.cn") or d.endswith(".edu"):
        return ("教育机构邮箱", "机构")
    if d.endswith(".gov.cn") or d.endswith(".gov"):
        return ("政府机构邮箱", "机构")
    if d.endswith(".ac.cn") or d.endswith(".ac.uk"):
        return ("科研机构邮箱", "机构")
    if d in DISPOSABLE:
        return ("一次性邮箱", "临时")
    return ("自建/企业域名", "自定义")


def mx_records(domain: str, timeout: int = 12) -> dict:
    """用系统 nslookup 查 MX。Windows 输出 GBK，Linux/Mac 是 UTF-8。"""
    exe = shutil.which("nslookup")
    if not exe:
        return {"ok": False, "records": [], "error": "系统没有 nslookup"}

    try:
        proc = subprocess.run(
            [exe, "-type=MX", domain],
            capture_output=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "records": [], "error": "DNS 查询超时"}
    except Exception as e:
        return {"ok": False, "records": [], "error": str(e)[:60]}

    out = proc.stdout.decode("gbk", "ignore")
    if not out.strip():
        out = proc.stdout.decode("utf-8", "ignore")

    records = []
    for pref, host in _MX_WIN.findall(out):
        records.append({"preference": int(pref), "host": host.rstrip(".")})
    if not records:
        for pref, host in _MX_UNIX.findall(out):
            records.append({"preference": int(pref), "host": host})

    records.sort(key=lambda r: r["preference"])
    ok = bool(records)
    return {
        "ok": ok,
        "records": records,
        "error": None if ok else "该域名没有 MX 记录，收不到邮件",
    }


def gravatar_hash(email: str) -> str:
    return hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()


def profile(raw: str, search: bool = False) -> dict:
    e = normalize(raw)
    out = {
        "input": raw,
        "email": e,
        "valid": is_valid(e),
        "local": None,
        "domain": None,
        "provider": None,
        "kind": None,
        "is_disposable": False,
        "mx_ok": None,
        "mx_records": [],
        "mx_error": None,
        "plus_alias": "+" in (e.split("@")[0] if "@" in e else ""),
        "hibp_url": None,
        "gravatar_md5": None,
        "hits": None,
    }
    if not out["valid"]:
        return out

    local, domain = e.rsplit("@", 1)
    out["local"], out["domain"] = local, domain
    provider, kind = lookup_provider(domain)
    out["provider"], out["kind"] = provider, kind
    out["is_disposable"] = domain in DISPOSABLE
    out["gravatar_md5"] = gravatar_hash(e)
    out["hibp_url"] = f"https://haveibeenpwned.com/account/{quote(e)}"

    mx = mx_records(domain)
    out["mx_ok"] = mx["ok"]
    out["mx_records"] = mx["records"]
    out["mx_error"] = mx["error"]

    if search:
        out["hits"] = public_mentions(e)

    return out


# ── 公开提及搜索 ────────────────────────────────────────
_TAG = re.compile(r"<[^>]+>")
_H2A = re.compile(r'<h2[^>]*>\s*<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>', re.S)
_SNIP = re.compile(r'<p[^>]*class="[^"]*b_lineclamp[^"]*"[^>]*>(.*?)</p>', re.S)


def _clean(s: str) -> str:
    import html as _h
    return _h.unescape(_TAG.sub("", s)).strip()


def public_mentions(email: str, limit: int = 20) -> dict:
    """必应搜邮箱。百度有强制验证码走不通。只保留正文真出现该邮箱的结果。"""
    url = ("https://www.bing.com/search?q=" + quote(f'"{email}"')
           + f"&count={limit}&setlang=zh-CN&cc=CN")
    page = net.get_text(url, timeout=20,
                        headers={"Cookie": "SRCHHPGUSR=SRCHLANG=zh-Hans"})
    hits, dropped = [], 0
    if not page:
        return {"hits": [], "dropped": 0, "error": "请求失败或被拦截"}

    for blk in page.split('<li class="b_algo"')[1:]:
        m = _H2A.search(blk)
        if not m:
            continue
        href, title = m.group(1), _clean(m.group(2))
        sm = _SNIP.search(blk) or re.search(r"<p[^>]*>(.*?)</p>", blk, re.S)
        snippet = _clean(sm.group(1)) if sm else ""
        # 必应无匹配时会返回推荐内容，正文里没有这个邮箱就是噪音
        if email.lower() not in f"{title} {snippet} {href}".lower():
            dropped += 1
            continue
        if href.startswith("/"):
            href = "https://www.bing.com" + href
        hits.append({"title": title, "url": href, "snippet": snippet})
    return {"hits": hits, "dropped": dropped, "error": None}


# ── 处置建议 ────────────────────────────────────────────
ADVICE = [
    {
        "title": "在 HIBP 查这个邮箱是否被拖库",
        "detail": "HaveIBeenPwned 收录了数百起公开泄露。邮箱命中说明密码哈希已外流，"
                  "如果那个密码你还在别处用，必须立刻改。",
        "how": "打开 {hibp_url}\n国内替代：https://monitor.mozilla.org",
        "priority": "必做",
    },
    {
        "title": "用别名隔离注册",
        "detail": "一个邮箱注册所有站，某站被拖库后主邮箱就成了垃圾邮件和撞库的靶子。",
        "how": "Gmail：name+站名@gmail.com（+ 号后面随便写，全进同一个收件箱）\n"
               "QQ 邮箱：设置 → 账户 → 英文别名\n"
               "Apple：设置 → Apple ID → 隐藏我的邮件\n"
               "独立方案：SimpleLogin / Firefox Relay",
        "priority": "建议",
    },
    {
        "title": "关闭「通过邮箱找到我」",
        "detail": "很多站默认允许用邮箱反查账号，等于把邮箱和身份绑在一起公开。",
        "how": "微信/QQ/微博等：隐私设置里找「通过邮箱搜索到我」并关闭\n"
               "GitHub：Settings → Emails → 取消 Keep my email addresses private 之外的公开项",
        "priority": "建议",
    },
    {
        "title": "一次性邮箱别用来注册重要账号",
        "detail": "临时邮箱收信即焚，一旦需要找回密码就彻底失去账号控制权。",
        "how": "重要账号（支付/社交主号/工作）只用长期邮箱，且开启二次验证",
        "priority": "建议",
    },
]
