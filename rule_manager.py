from enum import Enum, auto
from typing import Optional


class AppType(Enum):
    UNKNOWN = auto()
    HTTP = auto()
    HTTPS = auto()
    DNS = auto()
    TLS = auto()
    QUIC = auto()
    GOOGLE = auto()
    FACEBOOK = auto()
    YOUTUBE = auto()
    TWITTER = auto()
    INSTAGRAM = auto()
    NETFLIX = auto()
    AMAZON = auto()
    MICROSOFT = auto()
    APPLE = auto()
    WHATSAPP = auto()
    TELEGRAM = auto()
    TIKTOK = auto()
    SPOTIFY = auto()
    ZOOM = auto()
    DISCORD = auto()
    GITHUB = auto()
    CLOUDFLARE = auto()


def sni_to_app_type(sni: str) -> AppType:
    host = sni.lower()
    if 'youtube.com' in host or 'youtube' in host:
        return AppType.YOUTUBE
    if 'google.com' in host or 'google' in host or 'gstatic' in host:
        return AppType.GOOGLE
    if 'facebook.com' in host or 'fbcdn' in host or 'fb.com' in host:
        return AppType.FACEBOOK
    if 'twitter.com' in host:
        return AppType.TWITTER
    if 'instagram.com' in host:
        return AppType.INSTAGRAM
    if 'netflix.com' in host:
        return AppType.NETFLIX
    if 'amazon.com' in host or 'aws.amazon.com' in host:
        return AppType.AMAZON
    if 'microsoft.com' in host or 'office.com' in host or 'live.com' in host:
        return AppType.MICROSOFT
    if 'apple.com' in host:
        return AppType.APPLE
    if 'whatsapp.com' in host:
        return AppType.WHATSAPP
    if 'telegram.org' in host:
        return AppType.TELEGRAM
    if 'tiktok.com' in host:
        return AppType.TIKTOK
    if 'spotify.com' in host:
        return AppType.SPOTIFY
    if 'zoom.us' in host:
        return AppType.ZOOM
    if 'discord.com' in host or 'discordapp.com' in host:
        return AppType.DISCORD
    if 'github.com' in host:
        return AppType.GITHUB
    if 'cloudflare.com' in host:
        return AppType.CLOUDFLARE
    return AppType.HTTPS


def app_type_to_string(app: AppType) -> str:
    return app.name


class RuleManager:
    class BlockReason:
        def __init__(self, reason_type: str, detail: str) -> None:
            self.type = reason_type
            self.detail = detail

        def __str__(self) -> str:
            return f'{self.type}: {self.detail}'

    def __init__(self) -> None:
        self.blocked_ips: set[str] = set()
        self.blocked_apps: set[AppType] = set()
        self.blocked_domains: set[str] = set()
        self.blocked_ports: set[int] = set()

    def block_ip(self, ip: str) -> None:
        self.blocked_ips.add(ip)

    def block_app(self, app: AppType) -> None:
        self.blocked_apps.add(app)

    def block_domain(self, domain: str) -> None:
        self.blocked_domains.add(domain.lower())

    def block_port(self, port: int) -> None:
        self.blocked_ports.add(port)

    def should_block(self, src_ip: str, dst_port: int, app: AppType, domain: str) -> Optional[BlockReason]:
        if src_ip in self.blocked_ips:
            return RuleManager.BlockReason('IP', src_ip)
        if dst_port in self.blocked_ports:
            return RuleManager.BlockReason('PORT', str(dst_port))
        if app in self.blocked_apps:
            return RuleManager.BlockReason('APP', app_type_to_string(app))

        lower_domain = domain.lower()
        for rule in self.blocked_domains:
            if rule.startswith('*.'):
                suffix = rule[2:]
                if lower_domain == suffix or lower_domain.endswith('.' + suffix):
                    return RuleManager.BlockReason('DOMAIN', rule)
            elif rule == lower_domain or lower_domain.endswith('.' + rule):
                return RuleManager.BlockReason('DOMAIN', rule)

        return None
