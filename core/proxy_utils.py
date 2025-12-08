"""统一的代理配置工具模块。Unified proxy configuration utilities.

本模块提供从环境变量读取和解析代理配置的功能，支持 HTTP、HTTPS、SOCKS5、SOCKS4 等协议。
所有需要代理支持的模块都应使用本模块提供的函数，确保代理配置的一致性。
"""

from __future__ import annotations

import os
from typing import Dict, Optional


# 支持的代理协议前缀
_SUPPORTED_PROTOCOLS = ("http://", "https://", "socks5://", "socks4://")


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


def log_proxy_status(logger=None) -> None:
    """记录代理配置状态。

    Args:
        logger: 可选的 logger 对象，如果为 None 则使用 print()。
    """
    if not is_proxy_configured():
        message = "→ 未配置代理，将直连"
        if logger:
            logger.info(message)
        else:
            print(message)
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
