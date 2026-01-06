#!/bin/bash

# Docker 防火墙集成脚本
# 支持 firewalld、ufw、iptables
# 支持 CentOS、RHEL、Debian、Ubuntu、Rocky、AlmaLinux

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 输出函数
info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# 检查 root 权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "请使用 root 用户或 sudo 运行此脚本"
    fi
}

# 检测系统类型
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    elif [[ -f /etc/redhat-release ]]; then
        OS="centos"
    elif [[ -f /etc/debian_version ]]; then
        OS="debian"
    else
        error "无法检测操作系统类型"
    fi
    
    info "检测到系统: $OS $OS_VERSION"
}

# 检测已安装的防火墙
detect_installed_firewalls() {
    INSTALLED_FIREWALLS=""
    
    if command -v firewall-cmd &> /dev/null; then
        INSTALLED_FIREWALLS="$INSTALLED_FIREWALLS firewalld"
    fi
    
    if command -v ufw &> /dev/null; then
        INSTALLED_FIREWALLS="$INSTALLED_FIREWALLS ufw"
    fi
    
    if command -v iptables &> /dev/null; then
        INSTALLED_FIREWALLS="$INSTALLED_FIREWALLS iptables"
    fi
    
    if [[ -z "$INSTALLED_FIREWALLS" ]]; then
        error "未检测到任何防火墙工具"
    fi
    
    info "检测到已安装的防火墙:$INSTALLED_FIREWALLS"
}

# 检查 Docker 是否安装
check_docker() {
    if ! command -v docker &> /dev/null; then
        error "Docker 未安装，请先安装 Docker"
    fi
    
    if ! systemctl is-active --quiet docker; then
        warn "Docker 服务未运行，正在启动..."
        systemctl start docker
    fi
    
    success "Docker 已安装并运行"
}

# 获取 Docker 网络接口
get_docker_interfaces() {
    DOCKER_INTERFACES=$(docker network ls -q | xargs -I {} docker network inspect {} --format '{{.Options.com.docker.network.bridge.name}}' 2>/dev/null | grep -v "^$" | sort -u)
    
    # 添加默认的 docker0
    if ! echo "$DOCKER_INTERFACES" | grep -q "docker0"; then
        DOCKER_INTERFACES="docker0 $DOCKER_INTERFACES"
    fi
    
    info "检测到 Docker 网络接口: $DOCKER_INTERFACES"
}

# 获取 Docker 容器端口
get_docker_ports() {
    DOCKER_PORTS=$(docker ps --format '{{.Ports}}' | grep -oE '[0-9]+->|:[0-9]+->|0\.0\.0\.0:[0-9]+' | grep -oE '[0-9]+' | sort -u)
    
    if [[ -n "$DOCKER_PORTS" ]]; then
        info "检测到 Docker 容器端口: $(echo $DOCKER_PORTS | tr '\n' ' ')"
    else
        warn "未检测到正在运行的 Docker 容器端口"
    fi
}

# 询问用户选择防火墙
ask_firewall_choice() {
    echo ""
    echo "=========================================="
    echo "       Docker 防火墙集成配置脚本"
    echo "=========================================="
    echo ""
    echo "请选择你正在使用的防火墙:"
    echo ""
    echo "  1) firewalld  (CentOS/RHEL/Rocky/Fedora 默认)"
    echo "  2) ufw        (Ubuntu/Debian 常用)"
    echo "  3) iptables   (传统方式)"
    echo "  4) 自动检测并使用当前活动的防火墙"
    echo "  0) 退出"
    echo ""
    read -p "请输入选项 [0-4]: " choice
    
    case $choice in
        1)
            FIREWALL="firewalld"
            ;;
        2)
            FIREWALL="ufw"
            ;;
        3)
            FIREWALL="iptables"
            ;;
        4)
            auto_detect_active_firewall
            ;;
        0)
            info "退出脚本"
            exit 0
            ;;
        *)
            error "无效选项"
            ;;
    esac
    
    success "已选择防火墙: $FIREWALL"
}

# 自动检测活动的防火墙
auto_detect_active_firewall() {
    if systemctl is-active --quiet firewalld; then
        FIREWALL="firewalld"
    elif systemctl is-active --quiet ufw || ufw status 2>/dev/null | grep -q "Status: active"; then
        FIREWALL="ufw"
    elif systemctl is-active --quiet iptables || iptables -L &>/dev/null; then
        FIREWALL="iptables"
    else
        error "未检测到活动的防火墙"
    fi
    
    info "自动检测到活动防火墙: $FIREWALL"
}

# 询问是否添加端口
ask_add_ports() {
    echo ""
    read -p "是否需要开放额外的端口? [y/N]: " add_ports
    
    if [[ "$add_ports" =~ ^[Yy]$ ]]; then
        read -p "请输入要开放的端口 (多个端口用空格分隔，如: 80 443 8080): " EXTRA_PORTS
        info "将开放额外端口: $EXTRA_PORTS"
    else
        EXTRA_PORTS=""
    fi
}

# 配置 Docker daemon.json
configure_docker_daemon() {
    info "配置 Docker 禁用 iptables 管理..."
    
    DAEMON_JSON="/etc/docker/daemon.json"
    
    # 备份现有配置
    if [[ -f "$DAEMON_JSON" ]]; then
        cp "$DAEMON_JSON" "${DAEMON_JSON}.bak.$(date +%Y%m%d%H%M%S)"
        warn "已备份现有配置到 ${DAEMON_JSON}.bak.*"
        
        # 合并配置
        if command -v jq &> /dev/null; then
            jq '. + {"iptables": false}' "$DAEMON_JSON" > "${DAEMON_JSON}.tmp" && mv "${DAEMON_JSON}.tmp" "$DAEMON_JSON"
        else
            # 简单处理，如果没有 jq
            if grep -q "iptables" "$DAEMON_JSON"; then
                sed -i 's/"iptables":\s*true/"iptables": false/g' "$DAEMON_JSON"
            else
                # 在最后一个 } 前添加
                sed -i 's/}$/,\n  "iptables": false\n}/g' "$DAEMON_JSON"
            fi
        fi
    else
        mkdir -p /etc/docker
        cat > "$DAEMON_JSON" << 'EOF'
{
  "iptables": false
}
EOF
    fi
    
    success "Docker daemon.json 配置完成"
}

# ==================== firewalld 配置 ====================
configure_firewalld() {
    info "开始配置 firewalld..."
    
    # 检查 firewalld 状态
    if ! systemctl is-active --quiet firewalld; then
        warn "firewalld 未运行，正在启动..."
        systemctl start firewalld
        systemctl enable firewalld
    fi
    
    # 创建 docker zone（如果不存在）
    if ! firewall-cmd --get-zones | grep -q "docker"; then
        info "创建 docker zone..."
        firewall-cmd --permanent --new-zone=docker 2>/dev/null || true
    fi
    
    # 配置 docker zone
    firewall-cmd --permanent --zone=docker --set-target=ACCEPT
    
    # 将 Docker 接口添加到 docker zone
    for iface in $DOCKER_INTERFACES; do
        if [[ -n "$iface" ]] && ip link show "$iface" &>/dev/null; then
            info "将接口 $iface 添加到 docker zone..."
            firewall-cmd --permanent --zone=docker --change-interface="$iface" 2>/dev/null || true
        fi
    done
    
    # 启用 masquerade
    info "启用 NAT 转发..."
    firewall-cmd --permanent --zone=docker --add-masquerade
    firewall-cmd --permanent --zone=public --add-masquerade
    
    # 添加转发规则
    info "添加 Docker 网络转发规则..."
    for iface in $DOCKER_INTERFACES; do
        if [[ -n "$iface" ]]; then
            firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -i "$iface" -j ACCEPT 2>/dev/null || true
            firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -o "$iface" -j ACCEPT 2>/dev/null || true
        fi
    done
    
    # 开放 Docker 容器端口
    if [[ -n "$DOCKER_PORTS" ]]; then
        info "开放 Docker 容器端口..."
        for port in $DOCKER_PORTS; do
            firewall-cmd --permanent --add-port="${port}/tcp"
            success "已开放端口: ${port}/tcp"
        done
    fi
    
    # 开放额外端口
    if [[ -n "$EXTRA_PORTS" ]]; then
        info "开放额外端口..."
        for port in $EXTRA_PORTS; do
            firewall-cmd --permanent --add-port="${port}/tcp"
            success "已开放端口: ${port}/tcp"
        done
    fi
    
    # 重载防火墙
    info "重载 firewalld..."
    firewall-cmd --reload
    
    success "firewalld 配置完成"
}

# ==================== ufw 配置 ====================
configure_ufw() {
    info "开始配置 ufw..."
    
    # 检查 ufw 状态
    if ! ufw status | grep -q "Status: active"; then
        warn "ufw 未启用"
        read -p "是否启用 ufw? [y/N]: " enable_ufw
        if [[ "$enable_ufw" =~ ^[Yy]$ ]]; then
            ufw --force enable
        else
            error "ufw 未启用，无法继续配置"
        fi
    fi
    
    # 备份 ufw 配置
    cp /etc/ufw/before.rules /etc/ufw/before.rules.bak.$(date +%Y%m%d%H%M%S)
    warn "已备份 /etc/ufw/before.rules"
    
    # 检查是否已配置 Docker 规则
    if grep -q "DOCKER-USER" /etc/ufw/before.rules; then
        warn "检测到已有 Docker 规则，跳过添加"
    else
        info "添加 Docker NAT 规则..."
        
        # 获取默认网络接口
        DEFAULT_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
        
        # 在 *filter 之前添加 NAT 规则
        cat >> /etc/ufw/before.rules << EOF

# Docker NAT 规则 - 由脚本自动添加
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 172.16.0.0/12 -o $DEFAULT_IFACE -j MASQUERADE
-A POSTROUTING -s 192.168.0.0/16 -o $DEFAULT_IFACE -j MASQUERADE
-A POSTROUTING -s 10.0.0.0/8 -o $DEFAULT_IFACE -j MASQUERADE
COMMIT

EOF
    fi
    
    # 启用 IP 转发
    info "启用 IP 转发..."
    sed -i 's/#net\/ipv4\/ip_forward=1/net\/ipv4\/ip_forward=1/' /etc/ufw/sysctl.conf
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # 配置默认转发策略
    sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    
    # 允许 Docker 网络
    info "允许 Docker 网络..."
    for iface in $DOCKER_INTERFACES; do
        if [[ -n "$iface" ]]; then
            ufw allow in on "$iface" 2>/dev/null || true
            ufw allow out on "$iface" 2>/dev/null || true
        fi
    done
    
    # 开放 Docker 容器端口
    if [[ -n "$DOCKER_PORTS" ]]; then
        info "开放 Docker 容器端口..."
        for port in $DOCKER_PORTS; do
            ufw allow "${port}/tcp"
            success "已开放端口: ${port}/tcp"
        done
    fi
    
    # 开放额外端口
    if [[ -n "$EXTRA_PORTS" ]]; then
        info "开放额外端口..."
        for port in $EXTRA_PORTS; do
            ufw allow "${port}/tcp"
            success "已开放端口: ${port}/tcp"
        done
    fi
    
    # 重载 ufw
    info "重载 ufw..."
    ufw reload
    
    success "ufw 配置完成"
}

# ==================== iptables 配置 ====================
configure_iptables() {
    info "开始配置 iptables..."
    
    # 获取默认网络接口
    DEFAULT_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    info "默认网络接口: $DEFAULT_IFACE"
    
    # 启用 IP 转发
    info "启用 IP 转发..."
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # 持久化 IP 转发
    if [[ -f /etc/sysctl.conf ]]; then
        if ! grep -q "net.ipv4.ip_forward" /etc/sysctl.conf; then
            echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
        else
            sed -i 's/net.ipv4.ip_forward.*/net.ipv4.ip_forward = 1/' /etc/sysctl.conf
        fi
        sysctl -p
    fi
    
    # 创建 DOCKER-USER 链（如果不存在）
    iptables -N DOCKER-USER 2>/dev/null || true
    
    # 清空 DOCKER-USER 链
    iptables -F DOCKER-USER
    
    # 添加 NAT 规则
    info "添加 NAT 规则..."
    iptables -t nat -A POSTROUTING -s 172.16.0.0/12 -o "$DEFAULT_IFACE" -j MASQUERADE
    iptables -t nat -A POSTROUTING -s 192.168.0.0/16 -o "$DEFAULT_IFACE" -j MASQUERADE
    iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -o "$DEFAULT_IFACE" -j MASQUERADE
    
    # 允许 Docker 网络转发
    info "配置 Docker 网络转发..."
    for iface in $DOCKER_INTERFACES; do
        if [[ -n "$iface" ]]; then
            iptables -A FORWARD -i "$iface" -j ACCEPT
            iptables -A FORWARD -o "$iface" -j ACCEPT
        fi
    done
    
    # 允许已建立的连接
    iptables -A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # 开放 Docker 容器端口
    if [[ -n "$DOCKER_PORTS" ]]; then
        info "开放 Docker 容器端口..."
        for port in $DOCKER_PORTS; do
            iptables -A DOCKER-USER -p tcp --dport "$port" -j ACCEPT
            iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
            success "已开放端口: ${port}/tcp"
        done
    fi
    
    # 开放额外端口
    if [[ -n "$EXTRA_PORTS" ]]; then
        info "开放额外端口..."
        for port in $EXTRA_PORTS; do
            iptables -A DOCKER-USER -p tcp --dport "$port" -j ACCEPT
            iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
            success "已开放端口: ${port}/tcp"
        done
    fi
    
    # 返回到主链
    iptables -A DOCKER-USER -j RETURN
    
    # 保存规则
    info "保存 iptables 规则..."
    case $OS in
        centos|rhel|rocky|almalinux|fedora)
            if command -v iptables-save &> /dev/null; then
                iptables-save > /etc/sysconfig/iptables
            fi
            ;;
        debian|ubuntu)
            if command -v netfilter-persistent &> /dev/null; then
                netfilter-persistent save
            elif command -v iptables-save &> /dev/null; then
                mkdir -p /etc/iptables
                iptables-save > /etc/iptables/rules.v4
            fi
            ;;
    esac
    
    success "iptables 配置完成"
}

# 重启 Docker
restart_docker() {
    info "重启 Docker 服务..."
    systemctl restart docker
    
    # 等待 Docker 启动
    sleep 3
    
    if systemctl is-active --quiet docker; then
        success "Docker 服务重启成功"
    else
        error "Docker 服务重启失败，请检查日志: journalctl -xeu docker"
    fi
}

# 验证配置
verify_configuration() {
    echo ""
    echo "=========================================="
    echo "           配置验证"
    echo "=========================================="
    echo ""
    
    # 检查 Docker 状态
    info "Docker 状态:"
    docker ps --format "table {{.Names}}\t{{.Ports}}" 2>/dev/null || warn "无法获取 Docker 容器信息"
    echo ""
    
    # 检查防火墙状态
    case $FIREWALL in
        firewalld)
            info "firewalld 状态:"
            firewall-cmd --list-all
            echo ""
            info "Docker zone 状态:"
            firewall-cmd --zone=docker --list-all 2>/dev/null || true
            ;;
        ufw)
            info "ufw 状态:"
            ufw status verbose
            ;;
        iptables)
            info "iptables DOCKER-USER 链:"
            iptables -L DOCKER-USER -n -v
            echo ""
            info "iptables NAT 规则:"
            iptables -t nat -L POSTROUTING -n -v
            ;;
    esac
}

# 显示使用说明
show_usage() {
    echo ""
    echo "=========================================="
    echo "           配置完成"
    echo "=========================================="
    echo ""
    success "Docker 防火墙集成配置已完成！"
    echo ""
    echo "后续管理命令:"
    echo ""
    
    case $FIREWALL in
        firewalld)
            echo "  添加端口:    firewall-cmd --permanent --add-port=端口/tcp"
            echo "  删除端口:    firewall-cmd --permanent --remove-port=端口/tcp"
            echo "  重载规则:    firewall-cmd --reload"
            echo "  查看规则:    firewall-cmd --list-all"
            ;;
        ufw)
            echo "  添加端口:    ufw allow 端口/tcp"
            echo "  删除端口:    ufw delete allow 端口/tcp"
            echo "  查看规则:    ufw status"
            ;;
        iptables)
            echo "  添加端口:    iptables -A DOCKER-USER -p tcp --dport 端口 -j ACCEPT"
            echo "  删除端口:    iptables -D DOCKER-USER -p tcp --dport 端口 -j ACCEPT"
            echo "  查看规则:    iptables -L DOCKER-USER -n -v"
            ;;
    esac
    
    echo ""
    warn "注意: 添加新的 Docker 容器后，需要手动开放对应端口"
    echo ""
}

# 主函数
main() {
    echo ""
    check_root
    detect_os
    detect_installed_firewalls
    check_docker
    get_docker_interfaces
    get_docker_ports
    
    ask_firewall_choice
    ask_add_ports
    
    echo ""
    warn "即将进行以下操作:"
    echo "  1. 配置 Docker 禁用自动 iptables 管理"
    echo "  2. 配置 $FIREWALL 允许 Docker 网络转发"
    echo "  3. 开放 Docker 容器端口"
    echo "  4. 重启 Docker 服务"
    echo ""
    read -p "是否继续? [y/N]: " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        info "操作已取消"
        exit 0
    fi
    
    configure_docker_daemon
    
    case $FIREWALL in
        firewalld)
            configure_firewalld
            ;;
        ufw)
            configure_ufw
            ;;
        iptables)
            configure_iptables
            ;;
    esac
    
    restart_docker
    verify_configuration
    show_usage
}

# 运行主函数
main "$@"
