# taiji FTP 容器互通矩阵 — proftpd 镜像（多架构原生构建）
#
# 为什么自建而非拉取第三方 proftpd 镜像：上游 kibatic/proftpd 为 amd64-only，
# Apple Silicon 等主机经 QEMU 转译时匿名登录等路径不可靠；原生构建消除
# 转译伪象。Debian 官方 proftpd（含 mod_tls）即被测服务器本体。
# 用法：docker build -f proftpd.Dockerfile -t taiji-ftp-it-proftpd:matrix .
# 矩阵默认在镜像缺失时按本文件自建；TAIJI_FTP_IT_IMAGE_PROFTPD 可覆盖为
# 任意与该 CMD 契约一致的镜像引用。
FROM debian:trixie-slim
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends proftpd proftpd-mod-crypto; \
    rm -rf /var/lib/apt/lists/*; \
    sed -i 's/^#\?LoadModule mod_tls.c/LoadModule mod_tls.c/' /etc/proftpd/modules.conf
CMD ["/usr/sbin/proftpd", "--nodaemon"]
