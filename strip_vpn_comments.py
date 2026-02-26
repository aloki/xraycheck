#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Убирает комментарии (фрагмент после #) в VPN-конфигах построчно и добавляет новый:
  # <флаг_страны><AUTO_COMMENT>
Страна определяется по IP хоста прокси (ip-api.com).
AUTO_COMMENT задаётся переменной окружения (см. .env и workflow).
"""

import argparse
import os
import socket
import sys
import time
import urllib.request
from pathlib import Path

# Загружаем .env при локальном запуске
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Парсинг ссылки для извлечения хоста (address)
try:
    from lib.parsing import parse_proxy_url
except ImportError:
    parse_proxy_url = None

GEO_API = "http://ip-api.com/json/{ip}?fields=countryCode"
GEO_TIMEOUT = 3
GEO_DELAY = 0.2  # минимальная пауза между запросами (лимит API ~45/мин)

DEFAULT_AUTO_COMMENT = " verified · XRayCheck"


def get_auto_comment() -> str:
    """Текст комментария из переменной окружения AUTO_COMMENT."""
    return os.environ.get("AUTO_COMMENT", DEFAULT_AUTO_COMMENT).strip() or DEFAULT_AUTO_COMMENT


def strip_comment_from_line(line: str) -> str:
    """Убирает из строки фрагмент (комментарий) после первого '#'."""
    line = line.strip()
    if not line or line.startswith("#"):
        return line
    return line.split("#", 1)[0].strip()


def country_code_to_flag(cc: str) -> str:
    """Двухбуквенный код страны (ISO 3166-1 alpha-2) -> эмодзи флаг (региональные индикаторы)."""
    if not cc or len(cc) != 2:
        return "\U0001f310"  # globe
    a = 0x1F1E6  # regional indicator A
    return "".join(chr(a + ord(c) - ord("A")) for c in cc.upper() if "A" <= c <= "Z")


def get_host_from_link(link: str) -> str | None:
    """Извлекает хост (address) из прокси-ссылки."""
    if parse_proxy_url:
        parsed = parse_proxy_url(link)
        if parsed and isinstance(parsed.get("address"), str):
            return parsed["address"].strip()
    # Fallback: ищем @host:port в типичных схемах
    for prefix in ("vless://", "vmess://", "trojan://", "ss://", "hy2://", "hysteria2://", "hysteria://"):
        if link.startswith(prefix):
            rest = link[len(prefix) :].strip()
            if "?" in rest:
                rest = rest.split("?")[0]
            if "@" in rest:
                _, host_port = rest.rsplit("@", 1)
                if ":" in host_port:
                    return host_port.rpartition(":")[0].strip()
                return host_port.strip()
            if "://" in rest:
                return rest.split("/")[0].strip()
            break
    return None


def resolve_to_ip(host: str) -> str | None:
    """Возвращает IP для хоста или None при ошибке."""
    if not host:
        return None
    if host.replace(".", "").isdigit():
        return host
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, OSError):
        return None


def fetch_country_for_ip(ip: str, cache: dict) -> str:
    """Получает countryCode для IP через ip-api.com; использует cache."""
    if ip in cache:
        return cache[ip]
    time.sleep(GEO_DELAY)
    try:
        req = urllib.request.Request(GEO_API.format(ip=ip), headers={"User-Agent": "XRayCheck/1.0"})
        with urllib.request.urlopen(req, timeout=GEO_TIMEOUT) as r:
            import json
            data = json.loads(r.read().decode())
            cc = data.get("countryCode") or ""
            cache[ip] = cc
            return cc
    except Exception:
        cache[ip] = ""
        return ""


def process_file(
    input_path: str,
    output_path: str | None,
    add_comment: bool = True,
) -> int:
    """Читает файл, убирает комментарии, опционально добавляет новый с флагом страны, пишет результат."""
    path = Path(input_path)
    if not path.is_file():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 0
    out = Path(output_path) if output_path else path.parent / (path.stem + "_new" + path.suffix)
    lines_in = path.read_text(encoding="utf-8").splitlines()
    geo_cache: dict[str, str] = {}
    result = []
    for line in lines_in:
        link = strip_comment_from_line(line)
        if not link:
            continue
        if add_comment:
            host = get_host_from_link(link)
            ip = resolve_to_ip(host) if host else None
            cc = fetch_country_for_ip(ip, geo_cache) if ip else ""
            flag = country_code_to_flag(cc)
            link = f"{link}#{flag} {get_auto_comment().strip()}"
        result.append(link)
    out.write_text("\n".join(result) + ("\n" if result else ""), encoding="utf-8")
    print(f"Processed: {len(lines_in)} lines -> {len(result)} with new comment. Output: {out}")
    return len(result)


def main():
    parser = argparse.ArgumentParser(
        description="Strip comments from VPN configs and add: # <flag> verified · XRayCheck"
    )
    parser.add_argument("input", help="Input file (one link per line)")
    parser.add_argument("-o", "--output", default=None, help="Output file (default: <name>_new.<ext>)")
    parser.add_argument("--no-comment", action="store_true", help="Only strip comments, do not add new one")
    args = parser.parse_args()
    n = process_file(args.input, args.output, add_comment=not args.no_comment)
    sys.exit(0 if n > 0 else 1)


if __name__ == "__main__":
    main()
