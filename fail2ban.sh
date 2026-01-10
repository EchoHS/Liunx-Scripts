#!/bin/bash

# 检查是否以 root 身份运行，或者是否有 sudo 命令
check_root() {
    if [[ $EUID -eq 0 ]]; then
        # 已经是 root 用户，直接执行命令
        SUDO=""
    elif command -v sudo &> /dev/null; then
        # 有 sudo 命令
        SUDO="sudo"
    else
        echo "错误: 此脚本需要 root 权限运行。"
        echo "请使用以下方式之一运行此脚本:"
        echo "  1. 以 root 用户身份运行: su - 然后运行脚本"
        echo "  2. 安装 sudo: apt-get install sudo (需要先切换到 root)"
        exit 1
    fi
}

# 执行权限检查
check_root

# 判断系统类型
if [[ "$(uname)" == "Linux" ]]; then
    if [[ -f /etc/debian_version ]] || [[ -f /etc/lsb-release ]] || [[ -f /etc/os-release ]]; then
        # 安装 Fail2ban 和 python3-systemd（Debian/Ubuntu）
        $SUDO apt-get update
        $SUDO apt-get install -y fail2ban python3-systemd
    elif [[ -f /etc/centos-release ]] || [[ -f /etc/redhat-release ]]; then
        # 安装 Fail2ban（CentOS）
        # 注意：CentOS/RHEL 的日志后端可能也需要配置，但这里沿用原脚本逻辑
        $SUDO yum install -y fail2ban
    else
        echo "Unsupported Linux distribution"
        exit 1
    fi
else
    echo "Unsupported operating system"
    exit 1
fi

# 启动 Fail2ban（确保服务在配置前运行）
$SUDO systemctl start fail2ban

# 创建本地配置文件 /etc/fail2ban/jail.local
# 关键修复：
# 1. 针对 Debian 12，添加 backend = systemd
# 2. logpath 字段可以保留，但设置 backend=systemd 后，Fail2ban 实际上会使用 systemd journal
#    或者，您可以将 logpath 这一行移除或注释掉，让 Fail2ban 自动选择
$SUDO tee /etc/fail2ban/jail.local > /dev/null <<EOT
[sshd]
enabled = true
# 添加此行以解决 Debian 12 上的日志后端问题
backend = systemd
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = -1
EOT

# 重启服务以应用配置
$SUDO systemctl restart fail2ban
