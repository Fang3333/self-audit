"""命令行入口。

密码不要直接写在命令行里（会进 shell 历史），用 --password-file。
"""

from __future__ import annotations

import argparse
import os
import sys

from . import apis, email as email_mod, phone as phone_mod, playbook, pwned, report, wmn


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="audit",
        description="个人信息暴露面自查：账号枚举 + 手机号档案 + 密码泄露 + 处置清单",
    )
    ap.add_argument("-n", "--phone", action="append", default=[],
                    help="手机号，可多次指定。查号段属性并给平台自查路径")
    ap.add_argument("-e", "--email", action="append", default=[],
                    help="邮箱，可多次指定。查服务商、MX、临时邮箱判定")
    ap.add_argument("--email-search", action="store_true",
                    help="对邮箱额外跑一次公开网页搜索（较慢）")
    ap.add_argument("-u", "--username", action="append", default=[],
                    help="要查的用户名，可多次指定")
    ap.add_argument("-p", "--password", action="append", default=[],
                    help="要查的密码（会用 k-anonymity 查泄露）")
    ap.add_argument("--password-file", help="密码列表文件，每行一个。比 -p 安全")
    ap.add_argument("--cats", help="只扫这些分类，逗号分隔，先用 --list-cats 看有哪些")
    ap.add_argument("--limit", type=int, help="B 级最多扫多少个站（快速试跑）")
    ap.add_argument("--workers", type=int, default=32, help="并发数，默认 32")
    ap.add_argument("--skip-apis", action="store_true", help="跳过 A 级 API 检测")
    ap.add_argument("--skip-wmn", action="store_true", help="跳过 B 级社区规则扫描")
    ap.add_argument("--html", metavar="PATH", help="导出 HTML 报告")
    ap.add_argument("--json", metavar="PATH", help="导出 JSON")
    ap.add_argument("--list-cats", action="store_true", help="列出可扫的分类")
    ap.add_argument("--update-rules", action="store_true", help="强制重新下载站点规则")
    ap.add_argument("-q", "--quiet", action="store_true", help="不打印终端摘要")
    args = ap.parse_args(argv)

    if args.update_rules:
        try:
            p = wmn.fetch_rules(force=True)
        except wmn.RulesUnavailable as e:
            print(str(e), file=sys.stderr)
            return 3
        print(f"规则已更新: {p}")
        return 0

    if args.list_cats:
        try:
            cats = wmn.categories()
        except wmn.RulesUnavailable as e:
            print(str(e), file=sys.stderr)
            return 3
        for c, n in cats.items():
            print(f"{c:<16} {n:>4} 个站点")
        return 0

    passwords = list(args.password)
    if args.password_file:
        if not os.path.exists(args.password_file):
            print(f"文件不存在: {args.password_file}", file=sys.stderr)
            return 2
        with open(args.password_file, encoding="utf-8") as f:
            passwords += [ln.rstrip("\n") for ln in f if ln.strip()]

    if not args.username and not passwords and not args.phone and not args.email:
        ap.print_help()
        return 1

    api_results = []
    phone_results = []
    email_results = []
    scan = None
    pwn_results = None

    # 邮箱档案
    if args.email:
        for raw in args.email:
            email_results.append(email_mod.profile(raw, search=args.email_search))

    # 手机号档案
    if args.phone:
        for raw in args.phone:
            phone_results.append(phone_mod.profile(raw))

    # A 级：对所有用户名都查
    if args.username and not args.skip_apis:
        for u in args.username:
            for site in apis.CHECKS:
                r = apis.check(site, u)
                r["username"] = u
                api_results.append(r)

    # B 级：只对第一个用户名做全站扫描
    if args.username and not args.skip_wmn:
        cats = [c.strip() for c in args.cats.split(",")] if args.cats else None
        try:
            scan = wmn.scan(args.username[0], categories=cats,
                            workers=args.workers, limit=args.limit)
        except wmn.RulesUnavailable as e:
            print(str(e), file=sys.stderr)
            return 3

    if passwords:
        pwn_results = pwned.check_many(passwords)

    if not args.quiet:
        print(report.terminal(scan, pwn_results, api_results if api_results else None,
                              phone_results if phone_results else None,
                              email_results if email_results else None))

    if args.html:
        report.to_html(scan, pwn_results, api_results or None, args.html,
                       phone_results if phone_results else None,
                       email_results if email_results else None)
        if not args.quiet:
            print(f"\n[报告] {os.path.abspath(args.html)}")
    if args.json:
        report.to_json(scan, pwn_results, api_results or None, args.json,
                       phone_results if phone_results else None,
                       email_results if email_results else None)
        if not args.quiet:
            print(f"[JSON] {os.path.abspath(args.json)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
