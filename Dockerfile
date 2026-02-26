# Проверка VLESS в контейнере с доступом только к whitelist + хостам прокси
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    unzip \
    curl \
    ca-certificates \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Скачать Xray-core (Linux amd64) с GitHub
RUN set -eux; \
    API='https://api.github.com/repos/XTLS/Xray-core/releases/latest'; \
    URL=$(curl -sL "$API" | jq -r '.assets[] | select(.name == "Xray-linux-64.zip") | .browser_download_url'); \
    curl -sL "$URL" -o /tmp/xray.zip; \
    unzip -o /tmp/xray.zip -d /tmp/xe; \
    find /tmp/xe -type f -name xray -exec mv {} /usr/local/bin/ \;; \
    chmod +x /usr/local/bin/xray; \
    rm -rf /tmp/xray.zip /tmp/xe

# Скачать Hysteria 2 (Linux amd64) при сборке образа, чтобы не качать в рантайме
RUN set -eux; \
    HYSTERIA_URL='https://github.com/apernet/hysteria/releases/download/app/v2.4.2/hysteria-linux-amd64'; \
    curl -sL --connect-timeout 60 --retry 3 "$HYSTERIA_URL" -o /usr/local/bin/hysteria; \
    chmod +x /usr/local/bin/hysteria

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY vless_checker.py speedtest_checker.py hysteria_checker.py speedtest_hysteria.py ./
COPY lib/ ./lib/

# Пути к бинарникам в контейнере (избегаем скачивания в рантайме)
ENV XRAY_PATH=/usr/local/bin/xray
ENV HYSTERIA_PATH=/usr/local/bin/hysteria

# Точка входа: настройка iptables по whitelist + хостам прокси, затем запуск vless_checker.py
ENTRYPOINT ["python", "-m", "lib.docker_entrypoint"]
CMD []
