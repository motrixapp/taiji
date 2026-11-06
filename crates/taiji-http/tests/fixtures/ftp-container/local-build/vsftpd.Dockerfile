# taiji FTP 容器互通矩阵 — vsftpd 镜像（inetd 形态，多架构原生构建）
#
# 为什么自建而非拉取第三方 vsftpd 镜像：
# 1) 上游 fauria/vsftpd 为 amd64-only，Apple Silicon 等主机经 Rosetta/QEMU
#    转译时 vsftpd 的 fork+privsep 面不可靠；原生构建消除转译伪象。
# 2) vsftpd 3.0.3（上游最终版）的常驻监听形态在本矩阵环境一次成功 RETR 后
#    守护进程段错误退出（详见 tests/ftp_container_matrix.rs 模块文档）；
#    本镜像以 openbsd-inetd 承载（每连接独立 vsftpd 进程）规避该缺陷。
# 用法：docker build -f vsftpd.Dockerfile -t taiji-ftp-it-vsftpd:matrix .
# 矩阵默认在镜像缺失时按本文件自建；TAIJI_FTP_IT_IMAGE_VSFTPD 可覆盖为
# 任意与该 CMD 契约一致的镜像引用。
FROM debian:bookworm-slim
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends vsftpd openbsd-inetd; \
    rm -rf /var/lib/apt/lists/*; \
    mkdir -p /var/run/vsftpd/empty
# inetd 监听口经环境变量注入（明文 21 / 隐式 TLS 990）；inetd 每连接派生
# 独立 vsftpd 进程（该形态规避常驻监听形态的守护进程段错误缺陷）。
CMD ["sh", "-c", "printf '%s stream tcp nowait root /usr/sbin/vsftpd vsftpd /etc/vsftpd/taiji.conf\\n' \"${INETD_PORT:-21}\" > /etc/inetd.conf && exec /usr/sbin/inetd"]
