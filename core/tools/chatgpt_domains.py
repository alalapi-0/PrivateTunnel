"""ChatGPT/OpenAI 域名列表。ChatGPT/OpenAI domain list."""

from __future__ import annotations

from typing import Any


# ChatGPT/OpenAI 相关域名列表
CHATGPT_DOMAINS = [
    # 主要 API 域名
    "api.openai.com",
    "chat.openai.com",
    "platform.openai.com",
    
    # 认证相关
    "auth0.openai.com",
    "oauth.openai.com",
    "login.openai.com",
    
    # CDN 和静态资源
    "cdn.openai.com",
    "openaiapi-site.azureedge.net",
    
    # WebSocket 连接
    "chatgpt.com",
    "www.chatgpt.com",
    
    # API 端点
    "api2.openai.com",
    
    # 其他相关域名
    "help.openai.com",
    "status.openai.com",
]


# 扩展域名列表（可选，用于更全面的覆盖）
EXTENDED_CHATGPT_DOMAINS = CHATGPT_DOMAINS + [
    # 可能的备用域名
    "openai.azure.com",
    "openai-api.azure.com",
]


# IP 范围（如果已知，用于快速匹配）
CHATGPT_IP_RANGES = [
    # OpenAI 使用的 IP 范围（需要定期更新）
    # 这些是示例，实际需要从 DNS 解析获取
    "104.16.0.0/13",  # Cloudflare（OpenAI 使用 Cloudflare）
    "172.64.0.0/13",
]


def get_chatgpt_domains(extended: bool = False) -> list[str]:
    """获取 ChatGPT 域名列表。Get ChatGPT domain list.
    
    Args:
        extended: 是否包含扩展域名
    
    Returns:
        域名列表
    """
    if extended:
        return EXTENDED_CHATGPT_DOMAINS.copy()
    return CHATGPT_DOMAINS.copy()


def is_chatgpt_domain(domain: str) -> bool:
    """判断是否为 ChatGPT 域名。Check if domain is ChatGPT-related.
    
    Args:
        domain: 域名
    
    Returns:
        是否为 ChatGPT 域名
    """
    domain_lower = domain.lower()
    for chatgpt_domain in CHATGPT_DOMAINS:
        if domain_lower == chatgpt_domain or domain_lower.endswith(f".{chatgpt_domain}"):
            return True
    return False







