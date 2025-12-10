"""统一的代理配置工具模块。Unified proxy configuration utilities.

本模块提供从环境变量读取和解析代理配置的功能，支持 HTTP、HTTPS、SOCKS5、SOCKS4 等协议。
所有需要代理支持的模块都应使用本模块提供的函数，确保代理配置的一致性。
"""

from __future__ import annotations

import os
import socket
from typing import Any, Dict, Optional


# 支持的代理协议前缀
_SUPPORTED_PROTOCOLS = ("http://", "https://", "socks5://", "socks4://")

# 常见本地代理服务的默认端口
_COMMON_PROXY_PORTS = {
    "clash": 7890,           # Clash for Windows 默认 HTTP 端口
    "v2rayn": 10809,         # V2RayN 默认 HTTP 端口
    "shadowsocks": 1080,     # Shadowsocks 默认 SOCKS5 端口
    "clash_socks": 7891,     # Clash for Windows 默认 SOCKS5 端口
    "v2rayn_socks": 10808,   # V2RayN 默认 SOCKS5 端口
}


def _normalize_proxy_url(value: str) -> Optional[str]:
    """规范化代理 URL。

    Args:
        value: 代理 URL 字符串。

    Returns:
        规范化后的代理 URL，如果无效则返回 None。
    """
    if not value or not isinstance(value, str):
        return None

    value = value.strip()
    if not value:
        return None

    # 检查是否已有协议前缀
    value_lower = value.lower()
    has_protocol = any(value_lower.startswith(proto) for proto in _SUPPORTED_PROTOCOLS)

    if has_protocol:
        return value
    else:
        # 自动添加 http:// 前缀
        return f"http://{value}"


def _get_env_var_case_insensitive(name: str) -> Optional[str]:
    """从环境变量中读取值（大小写不敏感）。

    Args:
        name: 环境变量名。

    Returns:
        环境变量值，如果不存在或为空则返回 None。
    """
    # 先尝试精确匹配
    value = os.environ.get(name)
    if value and value.strip():
        return value.strip()

    # 尝试大写
    value = os.environ.get(name.upper())
    if value and value.strip():
        return value.strip()

    # 尝试小写
    value = os.environ.get(name.lower())
    if value and value.strip():
        return value.strip()

    # 检查所有环境变量（大小写不敏感）
    name_upper = name.upper()
    for env_key, env_value in os.environ.items():
        if env_key.upper() == name_upper:
            if env_value and env_value.strip():
                return env_value.strip()

    return None


def _check_port_listening(host: str, port: int, timeout: float = 1.0) -> bool:
    """检查指定主机和端口是否在监听。

    Args:
        host: 主机地址（通常是 "127.0.0.1"）
        port: 端口号
        timeout: 连接超时时间（秒）

    Returns:
        如果端口在监听返回 True，否则返回 False。
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def _test_http_proxy(host: str, port: int, timeout: float = 2.0) -> bool:
    """测试 HTTP 代理是否可用。

    Args:
        host: 代理主机地址
        port: 代理端口
        timeout: 超时时间（秒）

    Returns:
        如果代理可用返回 True，否则返回 False。
    """
    try:
        import requests
        proxies = {
            "http": f"http://{host}:{port}",
            "https": f"http://{host}:{port}",
        }
        # 尝试通过代理访问一个简单的 URL
        response = requests.get(
            "http://www.baidu.com",  # 使用国内可访问的 URL 进行测试
            proxies=proxies,
            timeout=timeout,
        )
        return response.status_code in (200, 301, 302, 303, 307, 308)
    except Exception:
        return False


def get_proxy_config() -> Optional[Dict[str, str]]:
    """从环境变量读取代理配置并返回标准格式。

    优先级：ALL_PROXY > HTTPS_PROXY > HTTP_PROXY

    Returns:
        代理配置字典，格式为 {"http": "proxy_url", "https": "proxy_url"}，
        如果没有配置代理则返回 None。
    """
    proxy_url: Optional[str] = None
    source_var: Optional[str] = None

    # 按优先级检查环境变量
    # 优先级：ALL_PROXY > HTTPS_PROXY > HTTP_PROXY
    if value := _get_env_var_case_insensitive("ALL_PROXY"):
        proxy_url = _normalize_proxy_url(value)
        source_var = "ALL_PROXY"
    elif value := _get_env_var_case_insensitive("HTTPS_PROXY"):
        proxy_url = _normalize_proxy_url(value)
        source_var = "HTTPS_PROXY"
    elif value := _get_env_var_case_insensitive("HTTP_PROXY"):
        proxy_url = _normalize_proxy_url(value)
        source_var = "HTTP_PROXY"

    if not proxy_url:
        return None

    # 返回标准格式：同时设置 http 和 https
    return {
        "http": proxy_url,
        "https": proxy_url,
    }


def get_proxy_for_urllib() -> Optional[Dict[str, str]]:
    """为 urllib 库提供代理配置。

    Returns:
        urllib 兼容的代理配置字典，如果没有配置代理则返回 None。
        格式与 get_proxy_config() 相同：{"http": "proxy_url", "https": "proxy_url"}
    """
    return get_proxy_config()


def is_proxy_configured() -> bool:
    """检查是否配置了代理（至少有一个代理环境变量）。

    Returns:
        如果配置了代理返回 True，否则返回 False。
    """
    for var_name in ("ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY"):
        value = _get_env_var_case_insensitive(var_name)
        if value and value.strip():
            return True
    return False


def detect_local_proxy(
    check_common_ports: bool = True,
    custom_ports: list[int] | None = None,
) -> Optional[Dict[str, Any]]:
    """自动检测本地代理服务。

    Args:
        check_common_ports: 是否检查常见代理端口（默认 True）
        custom_ports: 自定义端口列表（可选）

    Returns:
        如果检测到代理，返回包含代理信息的字典：
        {
            "proxy_url": "http://127.0.0.1:7890",
            "type": "http",
            "source": "detected",
            "port": 7890,
            "service": "clash"
        }
        如果没有检测到代理，返回 None。
    """
    localhost = "127.0.0.1"
    ports_to_check: list[int] = []

    # 添加常见端口
    if check_common_ports:
        ports_to_check.extend(_COMMON_PROXY_PORTS.values())

    # 添加自定义端口
    if custom_ports:
        ports_to_check.extend(custom_ports)

    # 去重并排序
    ports_to_check = sorted(set(ports_to_check))

    # 按顺序检测端口
    for port in ports_to_check:
        # 先检查端口是否在监听
        if not _check_port_listening(localhost, port):
            continue

        # 尝试检测代理类型（优先检测 HTTP 代理）
        if _test_http_proxy(localhost, port):
            # 确定服务名称
            service_name = "unknown"
            for name, default_port in _COMMON_PROXY_PORTS.items():
                if port == default_port:
                    service_name = name.split("_")[0]  # 移除 _socks 后缀
                    break

            return {
                "proxy_url": f"http://{localhost}:{port}",
                "type": "http",
                "source": "detected",
                "port": port,
                "service": service_name,
            }

    return None


def auto_configure_proxy(
    check_common_ports: bool = True,
    custom_ports: list[int] | None = None,
    set_environment: bool = False,
    logger=None,
) -> Optional[str]:
    """自动检测并配置代理。

    Args:
        check_common_ports: 是否检查常见代理端口（默认 True）
        custom_ports: 自定义端口列表（可选）
        set_environment: 是否自动设置环境变量（默认 False）
        logger: 可选的 logger 对象，如果为 None 则使用 print()

    Returns:
        如果检测到并配置了代理，返回代理 URL；否则返回 None。
    """
    # 如果已经配置了代理，直接返回
    if is_proxy_configured():
        proxy_config = get_proxy_config()
        if proxy_config:
            proxy_url = proxy_config.get("http") or proxy_config.get("https")
            if proxy_url:
                message = f"→ 已配置代理: {proxy_url}（来自环境变量）"
                if logger:
                    logger.info(message)
                else:
                    print(message)
                return proxy_url
        return None

    # 尝试检测本地代理
    detected = detect_local_proxy(check_common_ports, custom_ports)
    if not detected:
        message = "→ 未检测到本地代理服务"
        if logger:
            logger.info(message)
        else:
            print(message)
        return None

    proxy_url = detected["proxy_url"]
    service_name = detected.get("service", "unknown")

    # 如果设置了自动配置环境变量
    if set_environment:
        os.environ["ALL_PROXY"] = proxy_url
        message = f"→ 自动配置代理: {proxy_url} (检测到 {service_name}，已设置环境变量 ALL_PROXY)"
    else:
        message = f"→ 检测到本地代理: {proxy_url} (服务: {service_name})，建议设置环境变量 ALL_PROXY={proxy_url}"

    if logger:
        logger.info(message)
    else:
        print(message)

    return proxy_url


def log_proxy_status(logger=None, suggest_auto_detect: bool = True) -> None:
    """记录代理配置状态。

    Args:
        logger: 可选的 logger 对象，如果为 None 则使用 print()。
        suggest_auto_detect: 如果未配置代理，是否建议使用自动检测（默认 True）。
    """
    if not is_proxy_configured():
        message = "→ 未配置代理，将直连"
        if logger:
            logger.info(message)
        else:
            print(message)

        # 如果启用了建议，提示用户可以自动检测
        if suggest_auto_detect:
            hint = "（提示：可以使用 auto_configure_proxy() 自动检测本地代理）"
            if logger:
                logger.info(hint)
            else:
                print(hint)
        return

    # 查找配置的代理和来源
    proxy_url: Optional[str] = None
    source_var: Optional[str] = None

    for var_name in ("ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY"):
        value = _get_env_var_case_insensitive(var_name)
        if value and value.strip():
            normalized = _normalize_proxy_url(value)
            if normalized:
                proxy_url = normalized
                source_var = var_name
                break

    if proxy_url:
        message = f"→ 使用代理: {proxy_url} (来自环境变量 {source_var})"
        if logger:
            logger.info(message)
        else:
            print(message)
    else:
        message = "→ 未配置代理，将直连"
        if logger:
            logger.info(message)
        else:
            print(message)


def validate_proxy_config(
    timeout: float = 3.0,
    test_url: str = "http://www.baidu.com",
) -> tuple[bool, Optional[str]]:
    """验证代理配置是否可用。

    Args:
        timeout: 测试超时时间（秒）
        test_url: 用于测试的 URL（默认使用国内可访问的 URL）

    Returns:
        (是否可用, 错误消息)
        如果代理可用返回 (True, None)
        如果代理不可用返回 (False, 错误消息)
        如果没有配置代理返回 (True, None)（视为可用，因为会直连）
    """
    if not is_proxy_configured():
        return True, None

    proxies = get_proxy_config()
    if not proxies:
        return True, None

    try:
        import requests
    except ImportError:
        # 如果没有 requests 库，无法验证，返回 True（假设可用）
        return True, None

    try:
        response = requests.get(
            test_url,
            proxies=proxies,
            timeout=timeout,
            allow_redirects=True,
        )
        # 任何 2xx、3xx 或 4xx 状态码都表示代理工作（4xx 表示代理可达但目标服务器拒绝）
        if response.status_code < 500:
            return True, None
        else:
            return False, f"代理返回服务器错误: HTTP {response.status_code}"
    except requests.exceptions.ProxyError as exc:
        return False, f"代理连接失败: {str(exc)}"
    except requests.exceptions.Timeout:
        return False, f"代理连接超时（{timeout}秒）"
    except requests.exceptions.ConnectionError as exc:
        return False, f"代理连接错误: {str(exc)}"
    except Exception as exc:
        return False, f"代理验证失败: {str(exc)}"


def get_proxy_config_with_fallback(
    fallback_to_direct: bool = True,
    validate: bool = False,
) -> Optional[Dict[str, str]]:
    """获取代理配置，支持验证和降级。

    Args:
        fallback_to_direct: 如果代理验证失败，是否降级到直连（默认 True）
        validate: 是否验证代理可用性（默认 False，因为验证会增加延迟）

    Returns:
        代理配置字典，如果验证失败且 fallback_to_direct=True 则返回 None（表示直连）
    """
    if not is_proxy_configured():
        return None

    proxies = get_proxy_config()
    if not proxies:
        return None

    # 如果不需要验证，直接返回
    if not validate:
        return proxies

    # 验证代理
    is_valid, error_msg = validate_proxy_config()
    if is_valid:
        return proxies

    # 代理验证失败
    if fallback_to_direct:
        # 输出警告但不抛出异常
        import warnings
        warnings.warn(
            f"代理配置验证失败: {error_msg}，将降级到直连模式",
            UserWarning,
        )
        return None
    else:
        # 不降级，返回代理配置（让调用者处理错误）
        return proxies


def verify_proxy_on_startup(logger=None) -> bool:
    """在程序启动时验证代理配置（可选调用）。

    Args:
        logger: 可选的 logger 对象，如果为 None 则使用 print()。

    Returns:
        如果代理配置有效或未配置代理返回 True，否则返回 False。
    """
    if not is_proxy_configured():
        return True

    is_valid, error_msg = validate_proxy_config()
    if is_valid:
        message = "→ 代理配置验证通过"
        if logger:
            logger.info(message)
        else:
            print(message)
        return True
    else:
        message = f"⚠️ 代理配置验证失败: {error_msg}，程序将尝试直连"
        if logger:
            logger.warning(message)
        else:
            print(message)
        return False
