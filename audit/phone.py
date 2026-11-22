"""手机号档案：号段解析 + 归属地离线库 + 平台注册自查引导。

为什么没有「一键查出这个号对应的微信号/QQ/支付宝」：
微信、QQ、支付宝都不提供「按手机号查用户」的接口。它们的登录流程只认
验证码，不认查询。这一点是产品设计决定的，不是技术难度，绕不过去。
所以这里能自动给的只有号段属性，剩下的部分给可执行的人工路径。
"""

from __future__ import annotations

import json
import os
import re
import struct
import time

from . import net

_HOME = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DAT_PATH = os.path.join(_HOME, "phone.dat")
_DATA_URLS = [
    "https://cdn.jsdelivr.net/gh/pangongzi/phone@master/src/data/phone.dat",
    "https://fastly.jsdelivr.net/gh/pangongzi/phone@master/src/data/phone.dat",
]
MAX_AGE_DAYS = 90

# ── 号段 → 运营商 ────────────────────────────────────────
SEGMENTS: dict[str, tuple[str, bool, str]] = {}


def _add(carrier: str, prefixes: list[str], mvno: bool = False, note: str = "") -> None:
    for p in prefixes:
        SEGMENTS[p] = (carrier, mvno, note)


_add("中国移动", ["134", "135", "136", "137", "138", "139", "147", "148", "150", "151",
              "152", "157", "158", "159", "172", "178", "182", "183", "184", "187",
              "188", "195", "197", "198"])
_add("中国移动", ["165"], mvno=True, note="移动转售")
_add("中国联通", ["130", "131", "132", "145", "146", "155", "156", "166", "175", "176",
              "185", "186", "196"])
_add("中国联通", ["167", "170", "171"], mvno=True, note="联通转售")
_add("中国电信", ["133", "149", "153", "173", "177", "180", "181", "189", "190", "191",
              "193", "199"])
_add("中国电信", ["162"], mvno=True, note="电信转售")
_add("中国广电", ["192"])

IOT_PREFIXES = {"140", "141", "142", "143", "144", "146"}

LAUNCH_YEAR = {
    "130": 1995, "131": 1995, "132": 1997, "133": 1997, "134": 2004, "135": 2000,
    "136": 1999, "137": 1999, "138": 1997, "139": 1995, "145": 2009, "147": 2012,
    "148": 2016, "149": 2014, "150": 2007, "151": 2008, "152": 2008, "153": 2008,
    "155": 2008, "156": 2009, "157": 2008, "158": 2008, "159": 2008, "162": 2016,
    "165": 2018, "166": 2017, "167": 2016, "170": 2014, "171": 2015, "172": 2018,
    "173": 2016, "175": 2015, "176": 2015, "177": 2016, "178": 2016, "180": 2011,
    "181": 2011, "182": 2011, "183": 2012, "184": 2013, "185": 2012, "186": 2009,
    "187": 2010, "188": 2010, "189": 2008, "190": 2019, "191": 2018, "192": 2022,
    "193": 2019, "195": 2019, "196": 2019, "197": 2019, "198": 2018, "199": 2019,
}

_CLEAN = re.compile(r"[\s\-()（）+]")
_MOBILE = re.compile(r"^1[3-9]\d{9}$")

# 各平台「这个号注册了没有」的自查路径。没有可自动化的公开接口，
# 但每一步都能给出确定的判定标准，照着做就行。
PLATFORM_PROBE = [
    {
        "name": "微信",
        "path": "微信 → 添加朋友 → 手机联系人（需对方开启「通过手机号找到我」）",
        "verdict": "能搜到 = 该号绑定了微信，可见昵称、地区、朋友圈封面；搜不到不代表没号，可能只是关了开关",
    },
    {
        "name": "支付宝",
        "path": "支付宝 → 转账 → 转到支付宝账户 → 输入手机号",
        "verdict": "显示 `*X` 掩码姓名 = 已实名；提示「对方未开通支付宝」= 没注册",
    },
    {
        "name": "QQ",
        "path": "QQ → 添加好友 → 手机号查找（需对方开启）",
        "verdict": "搜到 = 绑定过 QQ",
    },
    {
        "name": "抖音",
        "path": "抖音登录页 → 手机号登录 → 输入号码点下一步",
        "verdict": "直接跳验证码 = 已注册；提示未注册 = 没号",
    },
    {
        "name": "微博",
        "path": "微博登录页 → 手机号登录 → 同上",
        "verdict": "同上。验证码不用真收，看跳转就行",
    },
    {
        "name": "小红书",
        "path": "小红书登录页 → 手机号登录",
        "verdict": "同上",
    },
    {
        "name": "淘宝",
        "path": "淘宝登录页 → 手机号登录",
        "verdict": "同上。淘宝号通常和支付宝是同一个",
    },
    {
        "name": "京东",
        "path": "京东登录页 → 手机号登录",
        "verdict": "同上",
    },
    {
        "name": "美团",
        "path": "美团登录页 → 手机号登录",
        "verdict": "同上",
    },
    {
        "name": "百度",
        "path": "passport.baidu.com → 手机号登录",
        "verdict": "同上",
    },
]

# 官方渠道，比任何爬虫都准
OFFICIAL = [
    {
        "name": "一证通查 · 名下手机卡",
        "how": "微信/支付宝搜小程序「一证通查」→ 移动电话卡查询 → 姓名+身份证+手机号，24h 内短信回结果",
        "value": "查出你身份证下有几张卡。多出来的就是被冒名办的，可申请注销",
    },
    {
        "name": "一证通查 2.0 · 互联网账号",
        "how": "同一小程序 → 互联网账号查询 → 勾选平台，48h 出结果",
        "value": "查出这个手机号在微信、QQ、淘宝、支付宝、抖音、微博、美团、京东、快手、B站等 16 个平台注册了几个账号",
    },
    {
        "name": "号码标记查询",
        "how": "码号服务推进组公众号，或运营商 App 里的号码标识",
        "value": "看这个号被第三方标记成什么（骚扰/诈骗/外卖），也能反映号被谁用过",
    },
]


def normalize(raw: str) -> str:
    s = _CLEAN.sub("", raw)
    if s.startswith("+86"):
        s = s[3:]
    elif s.startswith("86") and len(s) == 13:
        s = s[2:]
    return s


def is_valid(phone: str) -> bool:
    return bool(_MOBILE.match(phone))


# ── 离线归属地库 ────────────────────────────────────────
def _stale(path: str) -> bool:
    if not os.path.exists(path):
        return True
    return (time.time() - os.path.getmtime(path)) / 86400 > MAX_AGE_DAYS


def ensure_dat(path: str | None = None, force: bool = False) -> str | None:
    """确保本地有号段库。失败返回 None（号段规则仍然可用，只是没有归属地）。"""
    p = path or _DAT_PATH
    if not force and not _stale(p):
        return p
    for url in _DATA_URLS:
        status, body, _ = net.request(url, timeout=90, retries=0)
        if status != 200 or len(body) < 1_000_000:
            continue
        tmp = p + ".tmp"
        with open(tmp, "wb") as f:
            f.write(body)
        os.replace(tmp, p)
        return p
    return p if os.path.exists(p) else None


TYPE_MAP = {
    1: "中国移动", 2: "中国联通", 3: "中国电信",
    4: "中国电信（转售）", 5: "中国联通（转售）",
    6: "中国移动（转售）", 7: "中国广电",
}


class DatDB:
    """phone.dat：<4s i 头 + <i i B 索引(9字节) + 记录区 `省|市|邮编|区号\\0`。二分查找。"""

    def __init__(self, path: str):
        with open(path, "rb") as f:
            self.buf = f.read()
        hl = struct.calcsize("<4si")
        self.rl = struct.calcsize("<iiB")
        self.version, self.first = struct.unpack("<4si", self.buf[:hl])
        self.count = (len(self.buf) - self.first) // self.rl

    def lookup(self, phone: str) -> dict | None:
        if len(phone) < 7:
            return None
        key = int(phone[:7])
        lo, hi = 0, self.count - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            off = self.first + mid * self.rl
            pfx, roff, ptype = struct.unpack("<iiB", self.buf[off:off + self.rl])
            if pfx == key:
                end = self.buf.find(b"\x00", roff)
                parts = self.buf[roff:end if end > 0 else len(self.buf)
                                 ].decode("utf-8", "ignore").split("|")
                while len(parts) < 4:
                    parts.append("")
                return {
                    "province": parts[0] or None,
                    "city": parts[1] or None,
                    "postcode": parts[2] or None,
                    "area_code": parts[3] or None,
                    "carrier": TYPE_MAP.get(ptype),
                }
            if pfx < key:
                lo = mid + 1
            else:
                hi = mid - 1
        return None


_DB: DatDB | None = None


def _db() -> DatDB | None:
    global _DB
    if _DB is None:
        p = ensure_dat()
        if not p:
            return None
        try:
            _DB = DatDB(p)
        except Exception:
            return None
    return _DB


# ── 号码形态 ────────────────────────────────────────────
_SHAPE = [
    (r"(\d)\1{5,}", "六连号以上"),
    (r"(\d)\1{4}", "五连号"),
    (r"(\d)\1{3}", "四连号"),
    (r"(0123|1234|2345|3456|4567|5678|6789|9876|8765|7654|6543|5432|4321|3210)", "顺子"),
    (r"(\d\d)\1{2,}", "重复组"),
    (r"(520|1314|8888|6666|168)", "谐音号"),
]


def shape_tags(phone: str) -> list[str]:
    body = phone[3:]
    out = []
    for pat, name in _SHAPE:
        if re.search(pat, body) and name not in out:
            out.append(name)
    return out


def profile(raw: str, online: bool = False) -> dict:
    p = normalize(raw)
    valid = is_valid(p)
    out = {
        "input": raw,
        "phone": p,
        "valid": valid,
        "prefix7": p[:7] if len(p) >= 7 else None,
        "carrier": None,
        "is_mvno": None,
        "mvno_note": None,
        "is_iot": False,
        "segment_type": None,
        "province": None,
        "city": None,
        "area_code": None,
        "postcode": None,
        "launch_year": None,
        "number_age_max": None,
        "shape": [],
        "source": None,
    }
    if not valid:
        return out

    p3 = p[:3]
    if p3 in IOT_PREFIXES:
        out["is_iot"] = True
        out["carrier"] = "中国移动" if p3 != "146" else "中国联通"
        out["segment_type"] = "物联网/行业应用号段（不能收普通短信）"
        return out

    if p.startswith("1349"):
        out["carrier"] = "中国电信"
        out["is_mvno"] = True
        out["mvno_note"] = "电信转售（1349 专属号段）"
    else:
        hit = SEGMENTS.get(p3)
        if hit:
            out["carrier"], out["is_mvno"], out["mvno_note"] = hit
            out["segment_type"] = "移动转售" if hit[1] else "公众移动通信"

    out["shape"] = shape_tags(p)
    out["launch_year"] = LAUNCH_YEAR.get(p3)
    if out["launch_year"]:
        from datetime import datetime
        out["number_age_max"] = datetime.now().year - out["launch_year"]

    from datetime import datetime
    db = _db()
    if db:
        rec = db.lookup(p)
        if rec:
            out.update({k: rec[k] for k in ("province", "city", "area_code", "postcode")})
            if not out["carrier"] and rec.get("carrier"):
                out["carrier"] = rec["carrier"]
            out["source"] = f"phone.dat v{db.version.decode('ascii', 'ignore')}"

    return out


def to_json(prof: dict, path: str | None = None) -> str:
    txt = json.dumps(prof, ensure_ascii=False, indent=2)
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(txt)
    return txt
