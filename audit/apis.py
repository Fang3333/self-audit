"""A 级检测：有公开 API、返回结构化数据、能明确区分「存在/不存在」的站点。

和 WMN 规则相比，这里每一项都是实测校准过的：能通过 = 账号真存在，
不通 = 账号不存在，网络失败 = 记为 unknown，绝不并入「不存在」。

注意国内网络环境：Reddit、Docker Hub、Twitter/X、Facebook 等直连基本不通，
这些放在 WMN 里跑会得到一堆 unknown，反而污染报告。所以只保留能连的。
"""

from __future__ import annotations

import json
from typing import Callable

from . import net

# 判定函数返回 True=存在 / False=不存在 / None=不确定
Judge = Callable[[int, bytes], bool | None]


def _json_ok(key: str) -> Judge:
    """响应是 JSON 且含指定 key，且该 key 非 null。"""
    def f(status: int, body: bytes) -> bool | None:
        if status == 0:
            return None
        if status == 404:
            return False
        if status != 200:
            return None
        try:
            d = json.loads(body.decode("utf-8", "ignore"))
        except Exception:
            return None
        if not isinstance(d, dict):
            return None
        return bool(d.get(key))
    return f


def _hn(status: int, body: bytes) -> bool | None:
    """HackerNews 对不存在的用户返回字面量 null。"""
    if status == 0:
        return None
    if status != 200:
        return None
    txt = body.decode("utf-8", "ignore").strip()
    return txt not in ("null", "", "{}")


CHECKS: list[dict] = [
    {
        "name": "GitHub",
        "url": "https://api.github.com/users/{u}",
        "judge": _json_ok("login"),
        "cat": "代码托管",
        "risk": "高",
        "why": "公开仓库常带真实姓名、邮箱、公司、所在城市；commit 历史里有提交邮箱",
        "fix": "检查 profile 的 name/company/location/blog；git 全局邮箱改成 noreply 地址",
    },
    {
        "name": "Gitee",
        "url": "https://gitee.com/api/v5/users/{u}",
        "judge": _json_ok("login"),
        "cat": "代码托管",
        "risk": "高",
        "why": "同 GitHub，国内项目多，个人主页对外开放",
        "fix": "个人资料页检查真实姓名与公司；仓库里搜一下有没有提交 .env / 密钥",
    },
    {
        "name": "Hacker News",
        "url": "https://hacker-news.firebaseio.com/v0/user/{u}.json",
        "judge": _hn,
        "cat": "社区",
        "risk": "中",
        "why": "about 字段常写自我介绍，历史评论全部公开且无法删除",
        "fix": "about 里去掉真实姓名和联系方式",
    },
    {
        "name": "Keybase",
        "url": "https://keybase.io/_/api/1.0/user/lookup.json?username={u}",
        "judge": lambda s, b: None if s == 0 else (s == 200 and b'"basics"' in b),
        "cat": "加密身份",
        "risk": "中",
        "why": "会主动绑定 GitHub/Twitter/个人域名，等于把多个身份串成一条链",
        "fix": "不需要就直接注销；需要就检查绑定了哪些外部账号",
    },
    # PyPI 已移除：/user/{name}/ 对不存在的用户同样返回 200，无法区分，是纯假阳性源
]


def check(site: dict, username: str) -> dict:
    url = site["url"].replace("{u}", username)
    status, body, _ = net.request(url, timeout=12, retries=0)
    hit = site["judge"](status, body)
    return {
        "name": site["name"],
        "url": url,
        "cat": site["cat"],
        "risk": site["risk"],
        "status": "exists" if hit is True else ("absent" if hit is False else "unknown"),
        "http": status,
        "why": site["why"],
        "fix": site["fix"],
        "tier": "A",
    }
