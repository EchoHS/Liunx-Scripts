#!/bin/bash

# 判断系统类型
if [[ "$(uname)" == "Linux" ]]; then
    if [[ -f /etc/debian_version ]] || [[ -f /etc/lsb-release ]] || [[ -f /etc/os-release ]]; then
        # 安装 Fail2ban 和 python3-systemd（Debian/Ubuntu）
        sudo apt-get update
        sudo apt-get install -y fail2ban python3-systemd
    elif [[ -f /etc/centos-release ]] || [[ -f /etc/redhat-release ]]; then
        # 安装 Fail2ban（CentOS）
        # 注意：CentOS/RHEL 的日志后端可能也需要配置，但这里沿用原脚本逻辑
        sudo yum install -y fail2ban
    else
        echo "Unsupported Linux distribution"
        exit 1
    fi
else
    echo "Unsupported operating system"
    exit 1
fi

# 启动 Fail2ban（确保服务在配置前运行）
sudo systemctl start fail2ban

# 创建本地配置文件 /etc/fail2ban/jail.local
# 关键修复：
# 1. 针对 Debian 12，添加 backend = systemd
# 2. logpath 字段可以保留，但设置 backend=systemd 后，Fail2ban 实际上会使用 systemd journal
#    或者，您可以将 logpath 这一行移除或注释掉，让 Fail2ban 自动选择
sudo tee /etc/fail2ban/jail.local > /dev/null <<EOT
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
sudo systemctl restart fail2ban
