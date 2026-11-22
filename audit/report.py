"""报告输出：终端摘要 + 单文件 HTML。"""

from __future__ import annotations

import html as _h
import json
import unicodedata
from datetime import datetime

from . import email as email_mod, phone as phone_mod, playbook


def _w(s: str) -> int:
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in str(s))


def _pad(s: str, n: int) -> str:
    s = str(s)
    return s + " " * max(0, n - _w(s))


def terminal(scan: dict | None, pwn: list[dict] | None, apis: list[dict] | None,
             phones: list[dict] | None = None,
             emails: list[dict] | None = None) -> str:
    L = []
    bar = "─" * 66

    L.append(bar)
    L.append("  信息暴露面自查")
    L.append(bar)

    if phones:
        for pr in phones:
            L.append(f"\n  [手机号]  {pr['phone']}")
            if not pr["valid"]:
                L.append("    不是有效的中国大陆手机号")
                continue
            rows = [
                ("运营商", pr["carrier"]),
                ("号段类型", pr["segment_type"]),
                ("虚拟运营商", "是" if pr["is_mvno"] else "否"),
                ("归属地", f"{pr['province'] or '?'} {pr['city'] or ''}".strip()),
                ("区号", pr["area_code"]),
                ("号段投放", f"{pr['launch_year']} 年（号龄上限 {pr['number_age_max']} 年）"
                 if pr["launch_year"] else None),
                ("号码特征", "、".join(pr["shape"]) if pr["shape"] else None),
            ]
            w = max(_w(k) for k, _ in rows)
            for k, v in rows:
                L.append(f"    {_pad(k, w)} : {v if v else '—'}")
            L.append(f"    {'平台自查':<{w - 8}} : 共 {len(phone_mod.PLATFORM_PROBE)} 个平台，"
                     f"逐条路径见 HTML 报告")

    if emails:
        for em in emails:
            L.append(f"\n  [邮箱]  {em['email']}")
            if not em["valid"]:
                L.append("    格式不合法")
                continue
            rows = [
                ("服务商", em["provider"]),
                ("类型", em["kind"]),
                ("域名", em["domain"]),
                ("MX 记录", f"{len(em['mx_records'])} 条，可收信" if em["mx_ok"] else em["mx_error"]),
                ("一次性邮箱", "是" if em["is_disposable"] else "否"),
                ("+ 别名", "已使用" if em["plus_alias"] else None),
                ("HIBP 查询", em["hibp_url"]),
            ]
            w = max(_w(k) for k, _ in rows)
            for k, v in rows:
                L.append(f"    {_pad(k, w)} : {v if v else '—'}")
            if em.get("hits") is not None:
                hs = em["hits"].get("hits") or []
                L.append(f"    {'公开提及':<{w - 6}} : {len(hs)} 条"
                         + ("" if hs else "（未搜到，个人邮箱在公开网页痕迹很少）"))
                for h in hs[:5]:
                    L.append(f"        · {h['title'][:56]}")

    if apis:
        hit = [a for a in apis if a["status"] == "exists"]
        L.append(f"\n  [A 级·确定]  {len(hit)}/{len(apis)} 个站有账号")
        for a in apis:
            mark = {"exists": "● 有", "absent": "○ 无", "unknown": "? 未测通"}[a["status"]]
            L.append(f"    {_pad(a['name'], 14)} {mark:8} {a['url'][:52]}")

    if scan:
        st = scan["stats"]
        L.append(f"\n  [B 级·待复核]  {scan['username']} · 扫了 {scan['total']} 个站")
        L.append(f"    命中 {st['exists']}（其中二次验证通过 {st.get('confirmed',0)}）"
                 f"  无账号 {st['absent']}  未测通 {st['unknown']}")
        hits = [r for r in scan["results"] if r["status"] == "exists"]
        if hits:
            by_cat: dict[str, list] = {}
            for r in hits:
                by_cat.setdefault(r["cat"], []).append(r)
            for cat, items in sorted(by_cat.items(), key=lambda kv: -len(kv[1])):
                L.append(f"    · {cat} ({len(items)})")
                for r in items[:12]:
                    mark = "✓" if r.get("confidence") == "confirmed" else "?"
                    L.append(f"        {mark} {r['name']}")
                if len(items) > 12:
                    L.append(f"          … 另 {len(items)-12} 个")
            L.append("    ✓ = 页面里能找到该用户名，基本确定")
            L.append("    ? = 规则命中但页面没找到用户名，可能是误报")

    if pwn:
        L.append("\n  [密码泄露]")
        for p in pwn:
            if p.get("error"):
                L.append(f"    {_pad(p['masked'], 12)} 查询失败：{p['error']}")
                continue
            if p["pwned"]:
                L.append(f"    {_pad(p['masked'], 12)} ✗ 已泄露，出现 {p['count']:,} 次")
            else:
                L.append(f"    {_pad(p['masked'], 12)} ✓ 未在已知泄露中出现")
            s = p.get("strength") or {}
            if s:
                L.append(f"                  强度 {s.get('level')}  长度 {s.get('length')}")

    L.append("\n  [优先处置]")
    seen = set()
    n = 0
    for _, acts in playbook.all_sections():
        for a in acts:
            if a["priority"] != "必做" or a["title"] in seen:
                continue
            seen.add(a["title"])
            n += 1
            L.append(f"    {n}. {a['title']}")
            L.append(f"       {a['how'].splitlines()[0][:70]}")
    L.append(f"\n  完整清单（{sum(len(v) for _, v in playbook.all_sections())} 项）见 HTML 报告")
    return "\n".join(L)


# ── HTML ────────────────────────────────────────────────
def _badge(status: str) -> str:
    m = {
        "exists": ('<span class="b b-hit">有账号</span>'),
        "absent": ('<span class="b b-none">无</span>'),
        "unknown": ('<span class="b b-unk">未测通</span>'),
    }
    return m.get(status, "")


def _risk(r: str) -> str:
    cls = {"高": "r-high", "中": "r-mid", "低": "r-low"}.get(r, "r-low")
    return f'<span class="b {cls}">{_h.escape(r)}</span>'


def _email_block(em: dict) -> str:
    """邮箱区块：服务商 + MX 验证 + 一次性判定 + HIBP 入口 + 处置建议。"""
    esc = _h.escape
    if not em["valid"]:
        return (f"<h2>邮箱档案</h2><p class='sub'>{esc(em['email'])} "
                f"格式不合法，检查是否少了 @ 或域名。</p>")

    attrs = [
        ("邮箱", em["email"]),
        ("服务商", em["provider"]),
        ("类型", em["kind"]),
        ("域名", em["domain"]),
        ("域名可收信", "是" if em["mx_ok"] else "否"),
        ("一次性邮箱", "是" if em["is_disposable"] else "否"),
        ("+ 别名", "已使用" if em["plus_alias"] else "未使用"),
    ]
    grid = "".join(
        f'<div class="kv"><span>{esc(k)}</span><strong>{esc(str(v))}</strong></div>'
        for k, v in attrs
    )

    mx_rows = "".join(
        f'<tr><td class="mono">{r["preference"]}</td><td class="mono">{esc(r["host"])}</td></tr>'
        for r in em["mx_records"]
    )
    mx_html = (f'<table class="mx"><thead><tr><th style="width:90px">优先级</th>'
               f'<th>邮件服务器</th></tr></thead><tbody>{mx_rows}</tbody></table>'
               if mx_rows else
               f'<p class="sub">{esc(em["mx_error"] or "无 MX 记录")}</p>')

    advice = "".join(
        f'<div class="act"><div class="act-h">'
        f'<span class="b {"p-must" if a["priority"] == "必做" else "p-sug"}">{esc(a["priority"])}</span>'
        f'<strong>{esc(a["title"])}</strong></div>'
        f'<p>{esc(a["detail"])}</p>'
        f'<pre>{esc(a["how"].format(hibp_url=em["hibp_url"]))}</pre></div>'
        for a in email_mod.ADVICE
    )

    hits_html = ""
    if em.get("hits") is not None:
        hs = em["hits"].get("hits") or []
        if hs:
            lis = "".join(
                f'<li><a href="{esc(h["url"])}" target="_blank" rel="noreferrer">'
                f'{esc(h["title"])}</a><p>{esc(h["snippet"][:140])}</p></li>'
                for h in hs[:15]
            )
            hits_html = f"<h3 class='sec'>公开提及 · {len(hs)} 条</h3><ol class='hits'>{lis}</ol>"
        else:
            hits_html = ("<h3 class='sec'>公开提及</h3>"
                         "<p class='sub'>未搜到。个人邮箱在公开网页上痕迹很少，命中 0 属正常。</p>")

    return f"""
<h2>邮箱档案 · {esc(em["email"])}</h2>
<div class="kvgrid">{grid}</div>

<h3 class="sec">域名 MX 记录（能不能真收到信）</h3>
{mx_html}

<h3 class="sec">HIBP 泄露查询</h3>
<div class="official"><h4>该邮箱是否出现在公开拖库里</h4>
<p>HIBP 的账号查询需要付费 API key，工具不代查，直接给你链接——
打开后输入邮箱即可，网页查询免费。</p>
<pre>{esc(em["hibp_url"])}</pre></div>

<h3 class="sec">处置建议</h3>
<div class="acts plain">{advice}</div>
{hits_html}
"""


def _phone_block(pr: dict) -> str:
    """手机号区块：号段属性 + 平台自查路径 + 官方渠道。"""
    esc = _h.escape
    if not pr["valid"]:
        return (f"<h2>手机号档案</h2><p class='sub'>{esc(pr['phone'])} "
                f"不是有效的中国大陆手机号。</p>")

    attrs = [
        ("运营商", pr["carrier"]),
        ("号段类型", pr["segment_type"]),
        ("虚拟运营商", "是" if pr["is_mvno"] else "否"),
        ("归属地", f"{pr['province'] or '?'} {pr['city'] or ''}".strip()),
        ("区号", pr["area_code"]),
        ("号段投放", f"{pr['launch_year']} 年"),
        ("号龄上限", f"{pr['number_age_max']} 年" if pr["number_age_max"] else None),
        ("号码特征", "、".join(pr["shape"]) if pr["shape"] else None),
        ("数据来源", pr["source"]),
    ]
    grid = "".join(
        f'<div class="kv"><span>{esc(k)}</span><strong>{esc(str(v))}</strong></div>'
        for k, v in attrs if v
    )

    official = "".join(
        f'<div class="official"><h4>{esc(o["name"])}</h4>'
        f'<p>{esc(o["value"])}</p><pre>{esc(o["how"])}</pre></div>'
        for o in phone_mod.OFFICIAL
    )

    probes = "".join(
        f'<tr><td><strong>{esc(p["name"])}</strong></td>'
        f'<td class="path">{esc(p["path"])}</td>'
        f'<td class="verdict">{esc(p["verdict"])}</td></tr>'
        for p in phone_mod.PLATFORM_PROBE
    )

    return f"""
<h2>手机号档案 · {esc(pr['phone'])}</h2>
<div class="kvgrid">{grid}</div>

<h3 class="sec">官方渠道（准确率 100%，优先用这个）</h3>
<div class="officials">{official}</div>

<h3 class="sec">各平台注册自查 · 手动，但有确定判定标准</h3>
<p class="sub">没有公开接口能批量查这个。以下是每个平台的确定路径——
不用真收验证码，看跳转就能判断。</p>
<table class="probe"><thead><tr>
<th style="width:76px">平台</th><th>怎么操作</th><th style="width:38%">怎么判断</th>
</tr></thead><tbody>{probes}</tbody></table>
"""


def to_html(scan: dict | None, pwn: list[dict] | None, apis: list[dict] | None,
            path: str | None = None, phones: list[dict] | None = None,
            emails: list[dict] | None = None) -> str:
    esc = _h.escape
    parts = []

    # 概览
    total_hit = 0
    if apis:
        total_hit += sum(1 for a in apis if a["status"] == "exists")
    if scan:
        total_hit += scan["stats"]["exists"]
    pwn_hit = sum(1 for p in (pwn or []) if p.get("pwned"))

    parts.append(f"""
<div class="grid">
  <div class="kpi"><span class="n">{total_hit}</span><span class="l">个站点有你的账号</span></div>
  <div class="kpi{' warn' if pwn_hit else ''}"><span class="n">{pwn_hit}</span><span class="l">个密码已泄露</span></div>
  <div class="kpi"><span class="n">{scan['total'] if scan else 0}</span><span class="l">个站点被扫描</span></div>
</div>""")

    # 邮箱
    for em in (emails or []):
        parts.append(_email_block(em))

    # 手机号
    for pr in (phones or []):
        parts.append(_phone_block(pr))

    # A 级
    if apis:
        rows = "".join(
            f"<tr><td>{esc(a['name'])}</td><td>{_risk(a['risk'])}</td><td>{_badge(a['status'])}</td>"
            f"<td class='u'>{esc(a['url'])}</td></tr>"
            for a in apis
        )
        parts.append(f"<h2>A 级 · 确定结论</h2>"
                     f"<p class='sub'>用公开 API 直接判定，没有误报。未测通 = 网络不通，不等于没账号。</p>"
                     f"<table><thead><tr><th>站点</th><th>敏感度</th><th>结果</th><th>地址</th></tr></thead>"
                     f"<tbody>{rows}</tbody></table>")

    # B 级
    if scan:
        hits = [r for r in scan["results"] if r["status"] == "exists"]
        if hits:
            by_cat: dict[str, list] = {}
            for r in hits:
                by_cat.setdefault(r["cat"], []).append(r)
            blocks = []
            for cat, items in sorted(by_cat.items(), key=lambda kv: -len(kv[1])):
                lis = ""
                for r in items:
                    conf = r.get("confidence")
                    tag = ('<span class="b b-ok">确认</span>' if conf == "confirmed"
                           else '<span class="b b-doubt">疑似</span>')
                    lis += (f'<li>{tag}<a href="{esc(r["url"])}" target="_blank" '
                            f'rel="noreferrer">{esc(r["name"])}</a></li>')
                blocks.append(
                    f'<div class="catcard"><h3>{esc(cat)} <em>{len(items)}</em></h3>'
                    f'<ul class="hitlist">{lis}</ul></div>'
                )
            confirmed = sum(1 for r in hits if r.get("confidence") == "confirmed")
            parts.append(
                f"<h2>B 级 · 社区规则命中</h2>"
                f"<p class='sub'>共 {len(hits)} 个命中，其中 {confirmed} 个经二次验证（页面正文里"
                f"确实出现该用户名）。标「疑似」的请点开确认，站点改版会造成误报。</p>"
                f"<div class='cats'>{''.join(blocks)}</div>"
            )
        else:
            parts.append("<h2>B 级 · 社区规则命中</h2><p class='sub'>没有命中。"
                         "如果你平时用的用户名比较独特，这个结果是可信的。</p>")

    # 密码
    if pwn:
        rows = ""
        for p in pwn:
            if p.get("error"):
                rows += (f"<tr><td class='mono'>{esc(p['masked'])}</td>"
                         f"<td colspan='3' class='sub'>查询失败：{esc(p['error'])}</td></tr>")
                continue
            st = p.get("strength") or {}
            res = (f'<span class="b b-hit">泄露 {p["count"]:,} 次</span>' if p["pwned"]
                   else '<span class="b b-none">未发现</span>')
            rows += (f"<tr><td class='mono'>{esc(p['masked'])}</td><td>{res}</td>"
                     f"<td>{esc(st.get('level',''))}</td><td>{st.get('length','')} 位</td></tr>")
        parts.append(f"<h2>密码泄露</h2>"
                     f"<p class='sub'>k-anonymity 查询：只发送 SHA1 前 5 位，明文不出本机。"
                     f"「未发现」不代表绝对安全，只说明这个密码没在这批公开泄露里出现过。</p>"
                     f"<table><thead><tr><th>密码</th><th>结果</th><th>强度</th><th>长度</th></tr></thead>"
                     f"<tbody>{rows}</tbody></table>")

    # 处置
    secs = []
    for title, acts in playbook.all_sections():
        items = []
        for a in acts:
            how = "<br>".join(esc(x) for x in a["how"].splitlines())
            pr = a["priority"]
            cls = "p-must" if pr == "必做" else ("p-sug" if pr == "建议" else "p-opt")
            items.append(
                f'<div class="act"><div class="act-h"><span class="b {cls}">{esc(pr)}</span>'
                f'<strong>{esc(a["title"])}</strong></div>'
                f'<p>{esc(a["detail"])}</p><pre>{how}</pre></div>'
            )
        secs.append(f'<section><h3>{esc(title)}</h3>{"".join(items)}</section>')

    parts.append(f"<h2>处置清单</h2><div class='acts'>{''.join(secs)}</div>")

    doc = f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>信息暴露面自查报告</title>
<style>
:root{{--bg:#f5f6f8;--card:#fff;--line:#e4e7ec;--tx:#15181d;--mut:#697180;--ac:#2563eb;
--hi:#dc2626;--mid:#d97706;--lo:#059669}}
*{{box-sizing:border-box}}
body{{margin:0;padding:28px 20px 60px;background:var(--bg);color:var(--tx);
font:14px/1.7 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif}}
.wrap{{max-width:880px;margin:0 auto}}
h1{{font-size:21px;margin:0 0 4px;letter-spacing:-.2px}}
.sub{{color:var(--mut);font-size:12.5px;margin:2px 0 14px}}
h2{{font-size:16px;margin:34px 0 8px;padding-bottom:8px;border-bottom:1px solid var(--line)}}
h3{{font-size:13.5px;margin:0 0 10px;color:var(--mut);font-weight:600}}
.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:18px 0 8px}}
.kpi{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px}}
.kpi.warn{{border-color:#fbd5d5;background:#fffafa}}
.kpi .n{{display:block;font-size:26px;font-weight:600;line-height:1.2;letter-spacing:-.5px}}
.kpi.warn .n{{color:var(--hi)}}
.kpi .l{{font-size:12px;color:var(--mut)}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);
border-radius:12px;overflow:hidden;margin:8px 0}}
th,td{{padding:10px 14px;text-align:left;border-bottom:1px solid var(--line);font-size:13px}}
tr:last-child td{{border-bottom:0}}
thead th{{background:#fafbfc;color:var(--mut);font-weight:500;font-size:12px}}
td.u{{color:var(--mut);font-size:11.5px;word-break:break-all;max-width:280px}}
.mono{{font-family:ui-monospace,Consolas,monospace}}
.b{{display:inline-block;padding:1px 8px;border-radius:20px;font-size:11.5px;font-weight:500;
white-space:nowrap;border:1px solid transparent}}
.b-hit{{background:#fef2f2;color:var(--hi);border-color:#fbd5d5}}
.b-none{{background:#f0fdf7;color:var(--lo);border-color:#c8f0dd}}
.b-unk{{background:#f4f5f7;color:var(--mut);border-color:var(--line)}}
.r-high{{background:#fef2f2;color:var(--hi)}}
.r-mid{{background:#fffbeb;color:var(--mid)}}
.r-low{{background:#f4f5f7;color:var(--mut)}}
.b-ok{{background:#eff6ff;color:var(--ac);border-color:#c7dcfd;font-size:10.5px;margin-right:5px}}
.b-doubt{{background:#fffbeb;color:var(--mid);border-color:#fde68a;font-size:10.5px;margin-right:5px}}
.hitlist li{{display:flex;align-items:center;flex-wrap:wrap}}
.kvgrid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:1px;
background:var(--line);border:1px solid var(--line);border-radius:12px;overflow:hidden;margin:10px 0}}
.kv{{background:var(--card);padding:11px 14px}}
.kv span{{display:block;font-size:11.5px;color:var(--mut)}}
.kv strong{{font-size:13.5px;font-weight:600}}
h3.sec{{font-size:13px;color:var(--tx);margin:22px 0 8px;font-weight:600}}
.officials{{display:grid;gap:10px;margin:8px 0}}
.official{{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--lo);
border-radius:10px;padding:12px 16px}}
.official h4{{margin:0 0 4px;font-size:13.5px}}
.official p{{margin:2px 0 7px;color:#3d4450;font-size:12.5px}}
.official pre{{margin:0;background:#f7f8fa;border:1px solid var(--line);border-radius:7px;
padding:8px 11px;font-size:11.5px;white-space:pre-wrap;word-break:break-word;
font-family:ui-monospace,Consolas,monospace;color:#2a3038;line-height:1.6}}
table.probe td{{font-size:12.5px;vertical-align:top}}
table.probe td.path{{color:#3d4450}}
table.probe td.verdict{{color:var(--mut);font-size:12px}}
table.mx td{{font-size:12.5px}}
ol.hits{{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:12px 16px 12px 36px;margin:8px 0}}
ol.hits li{{margin:9px 0}}
ol.hits a{{color:var(--ac);text-decoration:none;font-weight:500}}
ol.hits a:hover{{text-decoration:underline}}
ol.hits p{{margin:2px 0 0;color:var(--mut);font-size:12px}}
.acts.plain section{{border:0;padding:0;margin:0;background:none}}
.acts.plain .act{{border-top:1px dashed var(--line);padding:12px 0}}
.acts.plain .act:first-child{{border-top:0;padding-top:0}}
.p-must{{background:#fef2f2;color:var(--hi)}}
.p-sug{{background:#eff6ff;color:var(--ac)}}
.p-opt{{background:#f4f5f7;color:var(--mut)}}
.cats{{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:12px;margin-top:10px}}
.catcard{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}}
.catcard h3{{display:flex;justify-content:space-between;align-items:center}}
.catcard em{{font-style:normal;color:var(--mut);font-size:11.5px;font-weight:400}}
.catcard ul{{margin:0;padding-left:16px}}
.catcard li{{font-size:12.5px;margin:3px 0}}
.catcard a{{color:var(--ac);text-decoration:none}}
.catcard a:hover{{text-decoration:underline}}
.acts section{{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:16px 18px;margin-bottom:12px}}
.act{{padding:12px 0;border-top:1px dashed var(--line)}}
.act:first-of-type{{border-top:0;padding-top:0}}
.act-h{{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:4px}}
.act p{{margin:2px 0 8px;color:#3d4450;font-size:12.8px}}
.act pre{{margin:0;background:#f7f8fa;border:1px solid var(--line);border-radius:8px;
padding:9px 12px;font-size:12px;line-height:1.65;white-space:pre-wrap;word-break:break-word;
font-family:ui-monospace,Consolas,monospace;color:#2a3038}}
.foot{{margin-top:32px;padding-top:14px;border-top:1px solid var(--line);
color:var(--mut);font-size:11.5px}}
@media(max-width:600px){{.grid{{grid-template-columns:1fr}}body{{padding:18px 14px 40px}}}}
</style></head><body><div class="wrap">
<h1>信息暴露面自查</h1>
<div class="sub">生成于 {datetime.now():%Y-%m-%d %H:%M} · 只查自己，只查公开信息</div>
{''.join(parts)}
<div class="foot">
边界：A 级为 API 精确判定；B 级为社区规则，站点改版会误报，需人工点开确认。<br>
「未测通」是网络原因，不代表没有账号。本报告不包含任何非公开数据。
</div>
</div></body></html>"""

    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(doc)
    return doc


def to_json(scan, pwn, apis, path: str | None = None,
            phones: list[dict] | None = None,
            emails: list[dict] | None = None) -> str:
    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "emails": emails or [],
        "phones": phones or [],
        "apis": apis,
        "username_scan": scan,
        "passwords": pwn,
    }
    txt = json.dumps(payload, ensure_ascii=False, indent=2)
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(txt)
    return txt
