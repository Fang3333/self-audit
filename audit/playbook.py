"""处置清单：把「发现了什么」映射到「具体做什么」。

每条都要求能落地——给到入口路径和开关名称，不给「加强安全意识」这种废话。
"""

from __future__ import annotations

# 手机号相关
PHONE_ACTIONS = [
    {
        "title": "工信部「一证通查」——查名下手机卡",
        "detail": "官方免费渠道，能查出你身份证下到底有几张手机卡。多出来的就是被冒名办的，"
                  "可以直接申请注销。这是唯一能查全的官方途径。",
        "how": "微信/支付宝搜小程序「一证通查」→ 移动电话卡查询 → 填姓名+身份证+手机号，"
               "24 小时内短信回复结果。网页版 hbjy.miit.gov.cn",
        "priority": "必做",
    },
    {
        "title": "工信部「一证通查 2.0」——查手机号注册了哪些互联网账号",
        "detail": "同一个入口，能查你的手机号在微信、QQ、淘宝、支付宝、抖音、微博、美团、"
                  "京东、快手、B站等 16 个平台注册了几个账号。查出陌生账号 = 你的号被人拿去注册过。",
        "how": "同一小程序 → 互联网账号查询 → 勾选要查的平台，48 小时内出结果",
        "priority": "必做",
    },
    {
        "title": "运营商号码标记查询",
        "detail": "手机号被第三方标记成「骚扰」「诈骗」「外卖」会影响别人接你电话，也能反映号码被谁用过。",
        "how": "移动：中国移动 App → 我的 → 号码标识；联通/电信类似，或搜「码号服务推进组」公众号查",
        "priority": "建议",
    },
    {
        "title": "关闭各平台的「通过手机号找到我」",
        "detail": "这是陌生人能拿你手机号反查到你账号的唯一通道。关掉之后别人拿号搜不到你，"
                  "代价是熟人也不能靠手机号加你。",
        "how": "微信：设置 → 朋友权限 → 添加我的方式 → 关「手机号」\n"
               "QQ：设置 → 隐私 → 发现我的方式 → 关「手机号」\n"
               "微博：设置 → 隐私设置 → 关闭「允许通过手机号搜索到我」\n"
               "抖音：设置 → 隐私设置 → 关闭「允许通过手机号找到我」\n"
               "小红书：设置 → 隐私 → 关闭「允许通过手机号找到我」",
        "priority": "建议",
    },
    {
        "title": "微信朋友圈陌生人可见",
        "detail": "默认「允许陌生人查看十条朋友圈」，等于把最近动态给所有能搜到你的人看。",
        "how": "微信：设置 → 朋友权限 → 朋友圈 → 关闭「允许陌生人查看十条朋友圈」",
        "priority": "建议",
    },
]

# 账号相关
ACCOUNT_ACTIONS = [
    {
        "title": "按重要性分级，别所有站一个密码",
        "detail": "分级：邮箱 > 支付/银行 > 社交主号 > 论坛/工具站。"
                  "邮箱是第一优先——它往往是所有其他账号的找回入口，邮箱被破等于全丢。",
        "how": "给邮箱和支付单独设强密码 + 开二次验证；低价值站点用一次性密码",
        "priority": "必做",
    },
    {
        "title": "开启二次验证（2FA）",
        "detail": "密码泄露了还有第二道门。优先给：邮箱、微信、QQ、GitHub、Gitee、Apple ID、支付宝。",
        "how": "优先用 TOTP（Google Authenticator / 微软 Authenticator / 1Password），"
               "短信验证码次之（可被 SIM 劫持）",
        "priority": "必做",
    },
    {
        "title": "注销不用的老账号",
        "detail": "暴露面 = 账号数 × 每个账号的信息量。十年不用的论坛号仍在泄露你的邮箱和历史发言。",
        "how": "本工具 B 级扫描出的站点，逐个判断是否还需要；不用的走「账号注销」流程"
               "（多数站在设置-账号-注销账号）",
        "priority": "建议",
    },
]

# 代码仓库
REPO_ACTIONS = [
    {
        "title": "git 提交邮箱改成 noreply",
        "detail": "每次 commit 都会把邮箱写进历史，公开仓库等于把邮箱挂出来，"
                  "而且能被 GitHub 关联到你所有其他仓库。",
        "how": "git config --global user.email \"<ID>+<用户名>@users.noreply.github.com\"\n"
               "GitHub 设置 → Emails → 勾选 Keep my email addresses private",
        "priority": "必做",
    },
    {
        "title": "扫一遍历史提交里的密钥",
        "detail": "很多人把 .env、云厂商 AK/SK、数据库密码提交过一次然后删掉——历史里还在。",
        "how": "pip install gitleaks 后用 `gitleaks detect --source . -v`；"
               "或 trufflehog filesystem . --only-verified",
        "priority": "建议",
    },
    {
        "title": "检查个人资料字段",
        "detail": "GitHub/Gitee 的 name、company、location、blog 四个字段最能定位到真人。",
        "how": "GitHub → Settings → Public profile；确认 location 不用写到区，company 不写真实单位",
        "priority": "建议",
    },
]

# 邮箱 / 密码
CRED_ACTIONS = [
    {
        "title": "查邮箱是否在已知拖库里",
        "detail": "HaveIBeenPwned 收录了数百起公开数据泄露。邮箱命中说明密码哈希已外流，"
                  "如果那个密码你还在别处用，必须立刻改。",
        "how": "https://haveibeenpwned.com 输入邮箱（网页免费）；"
               "国内可查 https://monitor.mozilla.org",
        "priority": "必做",
    },
    {
        "title": "用别名邮箱隔离注册",
        "detail": "一个邮箱注册所有站，一旦某站被拖库，你的主邮箱就成了垃圾邮件和撞库的靶子。",
        "how": "Apple「隐藏我的邮箱」、SimpleLogin、Firefox Relay；"
               "国内可用 QQ 邮箱的「英文别名」或 Gmail 的 + 后缀（如 name+shop@gmail.com）",
        "priority": "建议",
    },
    {
        "title": "被拖库过就换密码，别只改一位",
        "detail": "撞库工具会自动试 Password1 → Password2 这类变体，加个数字不算改。",
        "how": "换一个完全无关的新密码，并检查该站是否支持 2FA",
        "priority": "必做",
    },
]

# 物理世界 / 其他
MISC_ACTIONS = [
    {
        "title": "快递单和外卖地址",
        "detail": "快递面单上的姓名+手机号+门牌号是线下最常见的泄露源，丢件时整包信息一起走。",
        "how": "用驿站代收代替送上门；面单涂掉手机号中间四位再扔；"
               "外卖/快递 App 里用「隐私号码」功能",
        "priority": "建议",
    },
    {
        "title": "简历和求职平台",
        "detail": "招聘网站默认公开简历，姓名、手机、邮箱、工作经历全在上面，且被爬虫抓走。",
        "how": "BOSS直聘/智联/前程无忧：简历设「仅投递企业可见」，关闭「允许猎头搜索」",
        "priority": "建议",
    },
    {
        "title": "搜索引擎里的自己",
        "detail": "搜「姓名+手机号」「姓名+学校」看有没有被公开页面收录。",
        "how": "Google 有「关于你的个人信息」移除请求（需提供页面 URL）；"
               "百度用「百度搜索资源平台 → 删除快照」；学校/单位官网的公示名单可联系管理员下线",
        "priority": "可选",
    },
]


def all_sections() -> list[tuple[str, list[dict]]]:
    return [
        ("手机号", PHONE_ACTIONS),
        ("账号与密码", ACCOUNT_ACTIONS),
        ("代码仓库", REPO_ACTIONS),
        ("邮箱与凭据", CRED_ACTIONS),
        ("线下与其他", MISC_ACTIONS),
    ]


def for_findings(exists_sites: list[dict]) -> list[dict]:
    """按扫描结果挑出该优先处理的项。"""
    out = []
    cats = {s.get("cat", "") for s in exists_sites}
    names = {s.get("name", "").lower() for s in exists_sites}
    if cats & {"coding", "tech"} or names & {"github", "gitee"}:
        out.extend(REPO_ACTIONS)
    if exists_sites:
        out.extend(ACCOUNT_ACTIONS)
    return out
