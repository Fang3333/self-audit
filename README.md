# self-audit

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

**Audit your own digital footprint — not someone else's.**

A zero-dependency Python tool that tells you where your username has accounts, whether your
passwords appear in public breaches, and what to actually do about it. Built for the person
being checked, not the person checking.

```
$ python -m audit -u your_username --html report.html

  [A 级·确定]  3/4 个站有账号
    GitHub         ● 有      https://api.github.com/users/your_username
    Gitee          ○ 无
    Hacker News    ● 有
    Keybase        ● 有

  [B 级·待复核] 扫了 691 个站
    命中 65（其中二次验证通过 52）  无账号 235  未测通 391

  [密码泄露]
    p*********3  ✗ 已泄露，出现 2,266,677 次
                  强度 弱（词根+数字）
```

---

## 为什么做这个

市面上查人的工具一抓一大把，查自己该关哪些开关的几乎没有。

「我的信息泄露了吗」这个问题，实际上拆成三个能动手的部分：你的用户名在哪些站注册过、你的密码在不在公开拖库里、以及**发现之后具体该点哪里关掉**。前两个可以自动跑，第三个只能靠人整理——所以这个工具的输出重点在最后的处置清单。

**先说最重要的一条，代码解决不了的那部分：**

中国大陆用户查自己的手机号暴露面，用官方渠道，不用第三方工具——

微信或支付宝搜小程序「**一证通查**」：

- **名下手机卡查询**：你身份证下到底有几张手机卡。多出来的就是被冒名办的，能申请注销。
- **互联网账号查询 2.0**：你的手机号在微信、QQ、淘宝、支付宝、抖音、微博、美团、京东、快手、B站等 **16 个平台**注册了几个账号。查出陌生账号 = 号被人拿去注册过。

免费，48 小时内短信回复。这是唯一能查全的途径，任何爬虫都替代不了。工具里的处置清单把这条放在第一位，不是凑数。

## 安装

不需要安装。Python 3.9+，只用标准库：

```bash
git clone https://github.com/Fang3333/self-audit.git
cd self-audit
python -m audit --help
```

或者装成命令：

```bash
pip install .
self-audit --help
```

首次跑 B 级扫描时会自动从上游下载站点规则（约 250KB），之后缓存 30 天。规则数据不随仓库分发——vendored 进来的副本只会越来越失真。

## 用法

```bash
# 看有哪些分类
python -m audit --list-cats

# 手机号：号段属性 + 归属地 + 各平台自查路径
python -m audit -n 13800138000 --html 报告.html

# 用户名：A 级确定检测 + B 级 691 站
python -m audit -u 你的用户名 --html 报告.html

# 三个一起，一次出报告
python -m audit -n 13800138000 -u 你的用户名 --html 报告.html

# 只扫代码托管和社交
python -m audit -u 你的用户名 --cats coding,social

# 快速试跑
python -m audit -u 你的用户名 --limit 100

# 查密码泄露（别写命令行，会进 shell 历史）
echo "你的密码" > pw.txt
python -m audit --password-file pw.txt --html 报告.html
rm pw.txt

# 强制更新站点规则
python -m audit --update-rules
```

## 结果怎么读

这是这个工具唯一需要你认真看的地方。

| 档位 | 含义 | 该怎么用 |
|---|---|---|
| **A 级** | 站点有公开 API，返回结构化数据 | 直接信。没有误报 |
| **B 级 ✓ 确认** | 社区规则命中，且页面正文里确实出现该用户名 | 基本确定，可以开始处理 |
| **B 级 ? 疑似** | 规则命中但正文里找不到用户名 | 点开看一眼，多半是站点改版造成的误报 |
| **未测通** | 网络不通 | **不等于没账号**。这是最容易看错的一档 |

把「未测通」读成「没注册」，是这个工具唯一能让你产生错误安全感的地方，所以单列一档，绝不混进「无账号」。

二次验证是这么做的：社区规则命中后，再抓一次页面，检查正文里有没有这个用户名。实测对 `torvalds` 扫描，66 个原始命中经验证后剩 52 个确认，砍掉约八成误报。

## 手机号：为什么不能「一键全查」

这是这个工具被问得最多的问题，直接说结论——

**微信、QQ、支付宝都不提供「按手机号查用户」的接口。** 这不是技术难度问题，是产品设计：它们的登录流程只认验证码，不认查询。所谓「微信机器人」，只能操作**你自己**的账号，不能查别人；微信网页版协议 2017 年后对新号已关闭。

市面上号称「输入手机号全平台一键查」的只有一类东西：**社工库**。数据来自历年拖库，通常 5–15 年前的静态快照。你查到的很可能是前任机主，命中率低，还常掺假数据。持有和买卖这类数据本身违法。

所以这个工具的取舍是：**能自动给的给足，不能自动给的给确定的人工路径**。

自动能拿：运营商、是否虚商、是否物联网号段、归属省市、区号、号段投放年、号龄上限、靓号特征。

要人工但有确定判定的（报告里 10 个平台逐条列）：

| 平台 | 路径 | 判定 |
|---|---|---|
| 支付宝 | 转账 → 输入手机号 | 显示 `*X` 掩码姓名 = 已实名 |
| 微信 | 添加朋友 → 手机联系人 | 能搜到 = 绑定了（对方需开启开关） |
| 抖音/微博/小红书/淘宝/京东/美团/百度 | 登录页输入手机号点下一步 | 跳验证码 = 已注册，提示未注册 = 没号 |

验证码不用真收，看跳转就够了。

**最准的还是官方渠道**，工具里放在手机号区块最前面：

- **一证通查 · 名下手机卡**：查你身份证下有几张卡，多出来的是被冒名办的
- **一证通查 2.0**：查这个手机号在 16 个主流平台注册了几个账号，查出陌生账号 = 被人拿去注册过

免费，48 小时内短信回结果。任何爬虫都没这个准。

## 密码检测原理

用 HaveIBeenPwned 的 k-anonymity 接口，免费、无需 API key：

1. 本地计算 `SHA1(密码)`
2. 只把**前 5 位**发给服务端
3. 服务端返回该前缀下几十万条「后 35 位 + 泄露次数」
4. 本地匹配

明文密码和完整哈希都不离开本机。`password123` 实测命中 2,266,677 次。

「未发现」只说明这个密码没出现在这批公开泄露里，不代表它安全。

## 处置清单

报告最后一部分，17 条动作，每条给到入口路径和开关名：

```
微信：设置 → 朋友权限 → 添加我的方式 → 关「手机号」
QQ：  设置 → 隐私 → 发现我的方式 → 关「手机号」
git config --global user.email "<ID>+<用户名>@users.noreply.github.com"
gitleaks detect --source . -v
```

分三档：必做 / 建议 / 可选。不给「加强安全意识」这种废话。

## 项目结构

```
self-audit/
├── audit/
│   ├── phone.py       手机号：号段解析 + 归属地库（自动下载）+ 平台自查路径
│   ├── apis.py        A 级：GitHub / Gitee / HackerNews / Keybase，API 精确判定
│   ├── wmn.py         B 级：WhatsMyName 规则扫描 + 二次验证 + 规则自动更新
│   ├── pwned.py       HIBP k-anonymity + 密码强度评估
│   ├── playbook.py    处置清单（纯数据）
│   ├── report.py      终端 / HTML 报告
│   ├── net.py         HTTP 层（禁用系统代理、gzip 解压、超时重试）
│   └── cli.py         命令行入口
├── pyproject.toml
└── README.md
```

## 已知的坑

写在这里是免得别人重踩：

**4xx 响应也会 gzip 压缩。** 第一版 `net.py` 只在 200 分支解压，导致 404 的 body 是乱码——而账号枚举恰恰靠 404 判定，整个功能会静默失效。现在统一在 `_decode()` 里处理。

**PyPI 判不了。** `pypi.org/user/{name}/` 对不存在的用户同样返回 200 和同尺寸页面，无法区分，是纯假阳性源，已从 A 级移除。

**知乎对任意用户名返 200。** 不能用状态码判定。

**Gitee 上 `torvalds` 确实有账号**，但那是别人抢注的（`name` 字段是 `ken`），不是 Linus。用户名重合 ≠ 同一个人，这是所有人名枚举工具的通病。

**A 级为什么只有 4 个站。** Reddit、Docker Hub、Twitter/X、Facebook 在中国大陆直连全部不通，放进扫描只会产出「未测通」，污染报告。有代理的话改 `net.py` 里的 `ProxyHandler` 能放开很多。

**纯熵会高估密码强度。** `password123` 字符集够宽、长度够，按熵算是 57 bits「强」，必须加词根+数字、键盘序列这类模式识别才能判对。

## 边界

- 只查公开信息，不碰任何非公开数据。
- 用户名重合不等于同一个人。
- B 级规则来自 [WhatsMyName](https://github.com/WebBreacher/WhatsMyName)（MIT），站点改版就会失效，所以做了二次验证，但仍有残余误报。
- 中文平台（微博/抖音/小红书）没有可自动化的公开接口，只能走 App 里的「找回密码」手工探——跳验证码就说明注册过，不用真收。

## License

MIT
