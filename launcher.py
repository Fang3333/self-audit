"""双击入口：交互式收集参数，调用 audit，然后打开报告。

为什么要这一层：.bat 里的中文会受 cmd 代码页影响，在 UTF-8 终端里乱码。
把交互提示放在 Python 里，stdout 强制 UTF-8，跨终端就一致了。
"""

from __future__ import annotations

import os
import sys
import webbrowser

# Windows 控制台默认 GBK，强制 UTF-8 后中文才稳定
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
sys.path.insert(0, HERE)

REPORT = os.path.join(HERE, "我的报告.html")

BANNER = """
==================================================
    个人信息暴露面自查
==================================================

  问你什么就填什么，不想填的直接回车跳过。
  只查你自己 —— 输入的都是你自己的信息。
"""


def ask(label: str, hint: str = "") -> str:
    try:
        v = input(f"  {label}{('（' + hint + '）') if hint else ''}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n  已取消。")
        raise SystemExit(0)
    return v


def main() -> int:
    print(BANNER)

    u = ask("用户名", "比如 GitHub 用户名，可留空")
    p = ask("手机号", "11 位，可留空")
    e = ask("邮箱", "可留空")

    args = []
    if u:
        args += ["-u", u]
    if p:
        args += ["-n", p]
    if e:
        args += ["-e", e]

    if not args:
        print("\n  三个都空着，没什么可查的。回车退出。")
        try:
            input()
        except EOFError:
            pass
        return 0

    print("\n" + "-" * 50)
    print("  开始扫描，全量约 1-2 分钟，别关窗口")
    print("-" * 50 + "\n")

    from audit.cli import main as audit_main
    try:
        code = audit_main(args + ["--html", REPORT])
    except KeyboardInterrupt:
        print("\n  已中断。")
        return 130

    if code == 0 and os.path.exists(REPORT):
        print(f"\n  报告已生成，正在用浏览器打开……")
        print(f"  {REPORT}\n")
        try:
            webbrowser.open("file:///" + REPORT.replace("\\", "/"))
        except Exception:
            pass
    elif code == 0:
        print("\n  扫描完成但报告没生成，检查上面的输出。")
    else:
        print(f"\n  执行失败（退出码 {code}），往上翻看错误信息。")

    print("  按回车关闭窗口。")
    try:
        input()
    except EOFError:
        pass
    return code


if __name__ == "__main__":
    raise SystemExit(main())
