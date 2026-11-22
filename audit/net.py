"""统一 HTTP 请求层。

只依赖标准库。注意两点本机踩过的坑：
1. 系统里可能有残留代理（127.0.0.1:12450 / 54347）指向没有监听的端口，
   urllib 默认读 HTTP_PROXY 环境变量，会直接连死。所以一律 trust_env=False。
2. 国内站点对 UA 敏感，统一伪装桌面 Chrome。
"""

from __future__ import annotations

import gzip
import json
import ssl
import time
import urllib.error
import urllib.request
import zlib

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

# 不读系统代理环境变量
_OPENER_DIRECT = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def _decode(body: bytes, enc: str) -> bytes:
    """按 Content-Encoding 解压。4xx 响应同样会压缩，不能跳过。"""
    enc = (enc or "").lower()
    try:
        if "gzip" in enc:
            return gzip.decompress(body)
        if "deflate" in enc:
            return zlib.decompress(body, -zlib.MAX_WBITS)
    except Exception:
        # 头说 gzip 实际不是，原样返回，交给调用方按状态码判定
        pass
    return body


def request(
    url: str,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict | None = None,
    timeout: float = 8.0,
    retries: int = 1,
) -> tuple[int, bytes, dict]:
    """返回 (status, body_bytes, resp_headers)。网络异常时 status=0。"""
    hdrs = {
        "User-Agent": DEFAULT_UA,
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9",
        # 只要 gzip/deflate。标准库解不了 brotli，声明 br 会拿到乱码
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
    }
    if headers:
        hdrs.update(headers)

    last_err = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with _OPENER_DIRECT.open(req, timeout=timeout) as resp:
                body = _decode(resp.read(), resp.headers.get("Content-Encoding"))
                return resp.status, body, dict(resp.headers)
        except urllib.error.HTTPError as e:
            # 4xx/5xx 也是有效信息（账号枚举靠状态码 + body 特征判定）
            body = b""
            try:
                body = _decode(e.read(), (e.headers or {}).get("Content-Encoding"))
            except Exception:
                pass
            return e.code, body, dict(e.headers or {})
        except Exception as e:  # 超时 / DNS / 连接重置
            last_err = e
            if attempt < retries:
                time.sleep(0.6 * (attempt + 1))

    return 0, str(last_err).encode("utf-8", "ignore"), {}


def get_text(url: str, encoding: str | None = None, **kw) -> str:
    status, body, hdrs = request(url, **kw)
    if status == 0:
        return ""
    if encoding is None:
        ctype = (hdrs.get("Content-Type") or "").lower()
        if "gbk" in ctype or "gb2312" in ctype:
            encoding = "gbk"
        else:
            encoding = "utf-8"
    try:
        return body.decode(encoding, "ignore")
    except LookupError:
        return body.decode("utf-8", "ignore")


def get_json(url: str, **kw):
    txt = get_text(url, **kw)
    if not txt:
        return None
    txt = txt.strip()
    # 去掉 JSONP 包裹
    if txt[0] not in "{[":
        i, j = txt.find("{"), txt.rfind("}")
        if i >= 0 and j > i:
            txt = txt[i:j + 1]
    try:
        return json.loads(txt)
    except Exception:
        return None
