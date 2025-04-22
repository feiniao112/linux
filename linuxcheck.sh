#!/bin/bash

# ========================================================
# 工具名: Linux主机安全检查V2.0
# 作者: 飞鸟
# 版本:Create:201902 V1.0
#     Update:202504 V2.0

# 主要检查流程:
# 1. 基础环境检查：检测系统基本信息
# 2. 网络安全检查：检测网络接口、ARP欺骗、开放端口和网络连接
# 3. 系统安全检查：检测账户安全、启动项、计划任务、路由转发和进程
# 4. 配置安全检查：检测系统安全相关配置
# 5. 用户历史检查：检测用户历史命令
# 6. 文件安全检查：检测文件完整性和已删除打开文件
# 7. 日志安全检查：检测登录活动、dmesg日志和加载的内核模块
# 8. 恶意软件检查：检测恶意软件和系统性能
# 9. 后门检查：检测后门、防火墙配置、反弹Shell和库文件劫持
# 10. 日志备份：备份系统日志文件

# ========================================================


# 添加全局错误处理
set -e  # 遇到错误立即退出
trap 'echo "在第 $LINENO 行发生错误"; exit 1' ERR

# 定义目录变量
LOG_DIR="/var/log/security_check"
BACKUP_DIR="/var/log/backup"

# 定义日志文件和危险文件
IPADDR=$(ifconfig -a | grep -w inet | grep -v 127.0.0.1 | awk 'NR==1{print $2}' | cut -d':' -f2)
DATE=$(date +"%Y-%m-%d_%H-%M-%S")

LOG_FILE="${LOG_DIR}/linux_check_${IPADDR}_${DATE}.log"
DANGER_FILE="${LOG_DIR}/linux_danger_${IPADDR}_${DATE}.log"
BACKUP_FILE="${BACKUP_DIR}/logs_backup_${IPADDR}_${DATE}.zip"

# 创建日志目录和备份目录
mkdir -p $LOG_DIR
mkdir -p $BACKUP_DIR

# 添加日志轮转机制
LOG_MAX_SIZE=10M
LOG_BACKUP_COUNT=5

rotate_log() {
    if [ -f "$LOG_FILE" ] && [ $(stat -f%z "$LOG_FILE") -gt $LOG_MAX_SIZE ]; then
        for i in $(seq $((LOG_BACKUP_COUNT-1)) -1 1); do
            [ -f "${LOG_FILE}.$i" ] && mv "${LOG_FILE}.$i" "${LOG_FILE}.$((i+1))"
        done
        mv "$LOG_FILE" "${LOG_FILE}.1"
    fi
}

# 定义颜色变量
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# 优化日志函数
log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "【${timestamp}】:$1" | tee -a $LOG_FILE
}

log_danger() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "【${timestamp}】:[危险] $1" | tee -a $DANGER_FILE
}

log_warning() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "【${timestamp}】:[警告] $1" | tee -a $LOG_FILE
}

log_success() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "【${timestamp}】:[正常] $1\n" | tee -a $LOG_FILE
}

# 修改日志输出函数
log_complete() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "【${timestamp}】:$1" | tee -a $LOG_FILE
    echo "" | tee -a $LOG_FILE
}

# 检查是否为 root 用户
if [ "$(whoami)" != "root" ]; then
    echo "The security check must use the root account, otherwise some items cannot be checked"
    exit 1
fi

#检测系统基本信息
check_systeminfo() {
    local ret=0
    {
        log "[1] 开始检查系统信息..."
        # 检测 IP 地址
        log "[1.1] 开始检查IP地址..."
        ip_addresses=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}')
        if [ -z "$ip_addresses" ]; then
            log "未发现IP地址"
        else
            log "IP地址列表:"
            echo "$ip_addresses" | while IFS= read -r line; do
                log "  $line"
            done
        fi
        log_complete "IP地址检查完成"

        # 检测操作系统版本
        log "[1.2] 开始检查操作系统版本..."
        os_version=$(cat /etc/redhat-release)
        if [ -z "$os_version" ]; then
            log "无法获取操作系统版本"
        else
            log "操作系统版本: $os_version"
        fi
        log_complete "操作系统版本检查完成"
    } || ret=$?
    
    if [ $ret -ne 0 ]; then
        log_danger "系统信息检查失败，错误代码 $ret"
        return $ret
    fi
}

# 检测 ARP 表以及ARP攻击
check_arp_spoofing() {
    log "[2] 开始检查ARP欺骗"
    log "[2.1] 开始检查ARP表..."
    arp_table=$(arp -a)
    if [ -z "$arp_table" ]; then
        log "未发现ARP表项"
    else
        log "ARP表内容:"
        echo "$arp_table" | while IFS= read -r line; do
            log "  $line"
        done
    fi
    log_complete "ARP表检查完成"

    # 检测ARP攻击
    log "[2.2] 开始检测ARP欺骗..."
    arp_entries=$(arp -a | awk '{print $4}' | sort | uniq -c | sort -nr)
    if [ -z "$arp_entries" ]; then
        log "未发现ARP表项"
    else
        log "ARP表项统计:"
        echo "$arp_entries" | while IFS= read -r line; do
            count=$(echo $line | awk '{print $1}')
            mac=$(echo $line | awk '{print $2}')
            if [ "$count" -gt 1 ]; then
                log "发现潜在的ARP欺骗: MAC地址 $mac 出现 $count 次"
            else
                log "  $line"
            fi
        done
    fi
    log_complete "ARP欺骗检测完成"
}


check_open_port() {
    log "[3] 开始检查开放端口"
    # 检查开放的TCP端口和进程
    log "[3.1] 检查开放的TCP端口和对应进程..."
    tcpopen=$(netstat -anltp | grep LISTEN | awk '{print $4,$7}' | sed 's/:/ /g' | awk '{print $2,$3}' | sed 's/\// /g' | awk '{printf "%-20s%-10s\n", $1, $NF}' | sort -n | uniq)
    if [ -n "$tcpopen" ]; then
        log "服务器开放的TCP端口和对应进程如下:"
        echo "$tcpopen" | while IFS= read -r line; do
            log "  $line"
        done
    fi
    log_complete "系统未开放TCP端口"

    # 检查对外开放的TCP端口
    log "[3.2] 开始检查对外开放的TCP端口"
    tcpports=$(netstat -anltp | grep LISTEN | awk '{print $4}' | egrep "(0.0.0.0|:::)" | awk -F: '{print $NF}' | sort -n | uniq)
    if [ -n "$tcpports" ]; then
        log "以下TCP端口对外开放:"
        for port in $tcpports; do
            log "  $port"
        done 
    fi
    log_complete "没有对外开放的TCP端口"

    # 检测潜在危险的tcp端口
    log "[3.3] 开始检测潜在危险的TCP端口"
    dangerous_ports="21 22 23 25 135 137 138 139 143 3389 8080"
    open_ports=$(netstat -anltp | grep LISTEN | awk '{print $4}' | egrep "(0.0.0.0|:::)" | awk -F: '{print $NF}' | sort -n | uniq)
    if [ -n "$open_ports" ]; then
        for port in $open_ports; do
            if [[ " ${dangerous_ports[@]} " =~ " ${port} " ]]; then
                log "危险的TCP端口 $port 对外开放"
                log_danger "危险的TCP端口 $port 对外开放"
            fi
        done
    else
        log "未发现潜在危险的TCP端口"
    fi
    log_complete "潜在危险的TCP端口检查完成"

    # 检查开放的UDP端口
    log "[3.4] 开始检查开放的UDP端口和对应进程..."
    udpopen=$( netstat -anlup  | grep -v "udp6"| awk '{print $4,$NF}' | grep : | sed 's/:/ /g' | awk '{print $2,$3}' | sed 's/\// /g' | awk '{printf "%-20s%-10s\n", $1, $NF}' | sort -n | uniq)
    if [ -n "$udpopen" ]; then
        log "服务器开放的UDP端口和对应进程如下:"
        echo "$udpopen" | while IFS= read -r line; do
            log "  $line"
        done
    fi
        log_complete "检查完成"

    

    # 检测潜在危险的UDP端口
    log "[3.5] 开始检测潜在危险的UDP端口"
    dangerous_ports="137 138 161 162 500 1900 5353"
    open_ports=$(netstat -anlup | awk '{print $4}' | egrep "(0.0.0.0|:::)" | awk -F: '{print $NF}' | sort -n | uniq)
    if [ -n "$open_ports" ]; then
        for port in $open_ports; do
            if [[ " ${dangerous_ports[@]} " =~ " ${port} " ]]; then
                log_danger "[3.6] 危险的UDP端口 $port 对外开放"
            fi
        done
    fi
    log_complete "危险的UDP端口检查完成"
}


# 检测活动的网络连接
check_connections() {
    log "[4] 检查活动的网络连接..."
    active_connections=$(netstat -anp | grep -E 'tcp|udp' | grep ESTABLISHED)
    if [ -n "$active_connections" ]; then
        log "服务器存在以下活动的网络连接:"
        echo "$active_connections" | while IFS= read -r line; do
            log "  $line"
        done
    fi
    log_complete "检查完成"
}


# 查询威胁情报

# API 密钥
APIKEY=""

check_ip_threatbook() {
    log "[5] 开始检查IP威胁情报"
    ips=$(netstat -anltp | awk '{print $5}' | sed 's/:.*//' | grep -E '[0-9]' | grep -vwE "0.0.0.0|127.0.0.1" | uniq)
    for ip in $ips; do
        log "正在查询IP威胁情报: $ip"
        response=$(curl -s -X GET "https://api.threatbook.cn/v3/scene/ip_reputation?apikey=${APIKEY}&resource=$ip")   
        formatted_response=$(echo "$response" | jq .)
        log "IP $ip 的威胁情报结果:"
        log "$formatted_response"
        log_complete "IP威胁情报检查完成"
    done
}


# 检测网卡基本信息
check_interface() {
    log "[6] 开始检查网卡信息"
    log "[6.1] 检查网卡基本信息..."
    interfaces=$(ip link show | grep -oP '^\d+: \K\w+')
    if [ -n "$interfaces" ]; then
        for interface in $interfaces; do
            log "网卡: $interface"
            log "  IP信息:"
            ip addr show $interface 2>/dev/null | while read -r line; do
                log "  $line"
            done
            
            # 获取默认网关
            default_gateway=$(ip route | grep default | grep -oP 'via \K\S+' || echo "未找到")
            log "  默认网关: $default_gateway"
            
            # 获取 DNS 服务器
            if [ -f "/etc/resolv.conf" ]; then
                dns_servers=$(grep nameserver /etc/resolv.conf | awk '{print $2}')
                log "  DNS服务器: $dns_servers"
            else
                log "  未找到DNS配置文件"
            fi
            
            
            # 检测网卡是否处于混杂模式
            if ip link show $interface | grep -q PROMISC; then
                log_danger "网卡 $interface 处于混杂模式"
            else
                log_success "网卡 $interface 未处于混杂模式"
            fi
            
            # 检测网卡是否处于监听模式
            if command -v iw >/dev/null 2>&1; then
                if iw dev $interface info 2>/dev/null | grep -q "type monitor"; then
                    log_danger "网卡 $interface 处于监听模式"
                else
                    log_success "网卡 $interface 未处于监听模式"
                fi
            else
                log "未找到iw命令，跳过监听模式检查"
            fi
            
            # 获取传输速率
            if command -v ethtool >/dev/null 2>&1; then
                speed=$(ethtool $interface 2>/dev/null | grep -oP 'Speed: \K\S+' || echo "未知")
                log "  传输速率: $speed"
            else
                log "未找到ethtool命令，跳过速率检查"
            fi
            
            # 获取错误计数器
            if command -v ethtool >/dev/null 2>&1; then
                errors=$(ethtool -S $interface 2>/dev/null | grep -E 'rx_errors|tx_errors|rx_dropped|tx_dropped' || echo "未发现错误")
                log "  错误计数器:"
                echo "$errors" | while read -r line; do
                    log "    $line"
                done
            fi
        done
    else
        log_warning "未发现网卡"
    fi
    
    log_complete "网卡检查完成"
}


check_account() {
    log "[7] 开始检查账户信息"
    # 检查空口令用户
    log "[7.1] 开始检查空口令用户..."
    empty_password_users=$(sudo awk -F: '($2 == "") {print $1}' /etc/shadow)
    if [ -z "$empty_password_users" ]; then
        log "未发现空口令用户"
    else
        log_danger "发现空口令用户: $empty_password_users"
    fi
    log_complete "空口令用户检查完成"

    # 检查空口令且可以登录的用户
    log "[7.2] 开始检查空口令且可登录的用户..."
    empty_password_users=$(sudo awk -F: '($2 == "") {print $1}' /etc/shadow)
    if [ -z "$empty_password_users" ]; then
        log "未发现空口令用户"
    else
        log "发现空口令用户:"
        echo "$empty_password_users" | while IFS= read -r user; do
            login_shell=$(grep "^$user:" /etc/passwd | cut -d: -f7)
            if [ "$login_shell" != "/sbin/nologin" ] && [ "$login_shell" != "/usr/sbin/nologin" ]; then
                log_danger "发现空口令且可登录的用户: $user，登录Shell: $login_shell"
            else
                log "发现空口令但无法登录的用户: $user，登录Shell: $login_shell"
            fi
        done
    fi
    log_complete "空口令且可登录用户检查完成"

    # 检查超级用户
    log "[7.3] 开始检查超级用户..."
    superusers=$(awk -F: '($3 == 0) && ($1 != "root") {print $1}' /etc/passwd)
    if [ -z "$superusers" ]; then
        log "未发现超级用户"
    else
        log_danger "发现超级用户: $superusers"
    fi
    log_complete "超级用户检查完成"

    # 检查克隆账号
    log "[7.4] 开始检查克隆账号..."    
    log "[7.4.1] 检查具有相同用户名的账号..."
    duplicate_usernames=$(cut -d: -f1 /etc/passwd | sort | uniq -d)
    if [ -z "$duplicate_usernames" ]; then
        log "未发现具有相同用户名的账号"
    else
        log_danger "发现具有相同用户名的账号: $duplicate_usernames"
    fi
    log_complete "克隆账号检查完成"

    log "[7.4.2] 检查具有相同UID的账号..."
    duplicate_uids=$(cut -d: -f3 /etc/passwd | sort | uniq -d)
    if [ -z "$duplicate_uids" ]; then
        log "未发现具有相同UID的账号"
    else
        log_danger "发现具有相同UID的账号: $duplicate_uids"
        for uid in $duplicate_uids; do
            log_danger "UID为 $uid 的账号: $(grep ":$uid:" /etc/passwd)"
        done
    fi
    log_complete "相同UID的账号检查完成"

    # 检查可登录用户
    log "[7.5] 开始检测可登录用户..."
    valid_shells=$(getent passwd | awk -F: '($7 !~ /^(\/usr)?\/sbin\/nologin$|\/bin\/false$|\/usr\/lib\/gdm3\/gdm\-x\-session$/) {print $1}')
    while IFS= read -r user; do
        password_entry=$(sudo getent shadow "$user")
        if [[ -n "$password_entry" ]]; then
            password=$(echo "$password_entry" | cut -d: -f2)
            if ! echo "$password" | grep -qE '^\!|^\*'; then
                log "用户 $user 是一个有效的可登录用户"
            fi
        fi
    done <<< "$valid_shells"
    log_complete "可登录用户检测完成"

    # 检查非系统用户
    log "[7.6] 开始检查非系统用户..."
    non_system_users=$(awk -F: '($3 >= 1000) {print $1, $3, $7}' /etc/passwd)
    if [ -z "$non_system_users" ]; then
        log "未发现非系统用户"
    else
        log "发现以下非系统用户可以登录:"
        echo "$non_system_users" | while IFS=' ' read -r user uid shell; do
            log "用户: $user"
        done
    fi
    log_complete "非系统用户检查完成"
}


# 检测系统启动项
check_startup() {
    log "[8] 开始检查系统启动项"
    log "[8.1] 检查系统服务..."
    
    # 检查 Systemd 服务
    systemd_services=$(systemctl list-unit-files --state=enabled --type=service | awk 'NR>1 {print $1}' )
    if [ -n "$systemd_services" ]; then
        log "已启用的Systemd服务:"
        echo "$systemd_services" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "未发现已启用的Systemd服务"
    fi
    log_complete "检查完成"

    
    # 检查 /etc/rc.local
    log "[8.2] 检查/etc/rc.local文件..."
    if [ -f /etc/rc.local ]; then
        rc_local_content=$(cat /etc/rc.local)
        if [ -n "$rc_local_content" ]; then
            log "/etc/rc.local文件内容:"
            echo "$rc_local_content" | while IFS= read -r line; do
                log "  $line"
            done
        else
            log "/etc/rc.local文件为空"
        fi
    else
        log "/etc/rc.local文件不存在"
    fi
    log_complete "/etc/rc.local文件检查完成"
    
    # 检查 /etc/init.d 目录下的启动脚本
    log "[8.3] 检查/etc/init.d目录..."
    initd_scripts=$(ls -1 /etc/init.d/)
    if [ -n "$initd_scripts" ]; then
        log "/etc/init.d目录下的脚本:"
        for script in $initd_scripts; do
            if [ -x /etc/init.d/$script ]; then
                log "  $script"
            fi
        done
    else
        log "/etc/init.d目录下没有脚本"
    fi
    log_complete "/etc/init.d目录检查完成"
    
    # 检查 chkconfig 管理的启动项
    log "[8.4] 检查chkconfig管理的启动项..."
    if command -v chkconfig &> /dev/null; then
        chkconfig_items=$(chkconfig --list | grep -E ":on|启用|开" | awk '{print $1}' )
        if [ -n "$chkconfig_items" ]; then
            log "chkconfig管理的启动项:"
            echo "$chkconfig_items" | while IFS= read -r line; do
                log "  $line"
            done
        else
            log "未发现chkconfig管理的启动项"
        fi
    else
        log "未找到chkconfig命令"
    fi
    log_complete "系统启动项检查完成"
}


# 检测 Crontab 任务
check_crontab() {
    log "[9] 开始检查计划任务"
    # 检测用户级别的 Crontab 任务
    log "[9.1] 检查用户计划任务..."

    # 获取所有用户
    users=$(cut -d: -f1 /etc/passwd)
    # 检查每个用户的计划任务
    for user in $users; do
        output=$(sudo crontab -l -u $user 2>&1)
        if [[ $? -eq 0 ]] && ! echo "$output" | grep -q "no crontab for"; then
            log "用户 $user 的计划任务:"
            log "$output"
        fi
    done
    log_complete "用户计划任务检查完成"

    # 检测系统级别的定时任务
    log "[9.2] 检查系统级计划任务..."
    
    # 检查 /etc/crontab
    if [ -f /etc/crontab ]; then
        log "/etc/crontab文件内容:"
        cat /etc/crontab | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "/etc/crontab文件不存在"
    fi
    
    # 检查 /etc/cron.d 目录
    log "[9.3] 检查/etc/cron.d目录..."
    if [ -d /etc/cron.d ]; then
        log "/etc/cron.d目录内容:"
        for file in /etc/cron.d/*; do
            if [ -f "$file" ]; then
                log "  文件: $file"
                cat "$file" | while IFS= read -r line; do
                    log "    $line"
                done
            fi
        done
    else
        log "/etc/cron.d目录不存在"
    fi
    
    log "[9.4] 检查定时任务目录..."
    # 检查 /etc/cron.daily, /etc/cron.hourly, /etc/cron.monthly, /etc/cron.weekly
    for dir in /etc/cron.{daily,hourly,monthly,weekly}; do
        if [ -d "$dir" ]; then
            log "$dir"
            for file in "$dir"/*; do
                if [ -f "$file" ]; then
                    log  " $file"
                fi
            done
        else
            log "目录 $dir 不存在"
        fi
    done
    log_complete "计划任务检查完成"
}


# 检测路由和转发
check_routing_forwarded() {
    log "[10] 开始检查路由和转发"
    log "[10.1] 检查路由表..."
    # 检测路由
    routing_table=$(route -n)
    if [ -n "$routing_table" ]; then
        log "路由表条目:"
        echo "$routing_table" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "未发现路由表条目"
    fi
    log_complete "路由表检查完成"
    # 检测 IP 转发设置
    log "[10.2] 检查IPv4转发设置..."
    # 检查 IPv4 转发
    ipv4_forward=$(sysctl net.ipv4.ip_forward | awk '{print $3}')
    if [ "$ipv4_forward" -eq 1 ]; then
        log "IPv4转发已启用"
    else
        log "IPv4转发已禁用"
    fi
    log_complete "IPv4转发设置检查完成"

    # 检查 IPv6 转发
    log "[10.3] 检查IPv6转发设置..."
    ipv6_forward=$(sysctl net.ipv6.conf.all.forwarding | awk '{print $3}')
    if [ "$ipv6_forward" -eq 1 ]; then
        log "IPv6转发已启用"
    else
        log "IPv6转发已禁用"
    fi
    log_complete "IPv6转发设置检查完成"
}


# 检测进程
check_processes() {
    log "[11] 开始检查进程"
    log "[11.1] 检查所有进程..." 
    # 获取所有进程信息
    processes=$(ps aux)
    if [ -n "$processes" ]; then
        log "所有进程:"
        echo "$processes" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "未发现进程"
    fi
    log_complete "所有进程检查完成"

    # 检测高资源消耗的进程
    log "[11.2] 检查高资源消耗的进程..."
    # 获取CPU和内存使用率前10的进程
    high_cpu=$(ps aux --sort=-%cpu | head -n 11)
    high_mem=$(ps aux --sort=-%mem | head -n 11)
    
    if [ -n "$high_cpu" ]; then
        log "高CPU使用率的进程:"
        echo "$high_cpu" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "未发现高CPU使用率的进程"
    fi
    log_complete "高CPU使用率的进程检查完成"

    if [ -n "$high_mem" ]; then
        log "高内存使用率的进程:"
        echo "$high_mem" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "未发现高内存使用率的进程"
    fi
    log_complete "高内存使用率的进程检查完成"

    # 检测隐藏进程
    log "[11.3] 检查隐藏进程..."
    
    # 检查 /proc 目录下是否有隐藏的 PID
    hidden_pids=$(ls -l /proc/ | grep -oP '^\d+' | sort -n | uniq)
    if [ -n "$hidden_pids" ]; then
        for pid in $hidden_pids; do
            if ! ps -p $pid > /dev/null 2>&1; then
                log_danger "发现隐藏进程: PID $pid"
            fi
        done
    else
        log "未发现隐藏进程"
    fi
    log_complete "隐藏进程检查完成"
}



# 检测重要的文件和配置
check_config() {

    log "[12] 开始检查重要的文件和配置"
    # 检测 hosts 文件
    log "[12.1] 检查/etc/hosts文件..."
    
    if [ -f /etc/hosts ]; then
        log "/etc/hosts文件内容:"
        cat /etc/hosts | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "/etc/hosts文件不存在"
    fi
    log_complete "hosts文件检查完成"

    # 检测 DNS 配置
    log "[12.2] 检查DNS配置..."
    
    if [ -f /etc/resolv.conf ]; then
        log "/etc/resolv.conf文件内容:"
        cat /etc/resolv.conf | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "/etc/resolv.conf文件不存在"
    fi
    log_complete "DNS配置检查完成"
    # 检测 Nginx 配置文件
    log "[12.3] 检查Nginx配置文件..."
    #检查是否加载了第三方.so文件
    load_modules=$(grep -i 'load_module' /etc/nginx/nginx.conf)
    if [ -n "$load_modules" ]; then
        log "已加载第三方.so文件:"
        echo "$load_modules" | while IFS= read -r module; do
            log "  $module"
        done
    else
        log "未加载第三方.so文件"
    fi
    log_complete "Nginx配置文件检查完成"

    # 检查 proxy_pass,以检测可能存在的hosts碰撞攻击
    log "[12.4]开始检查proxy_pass"
    proxy_pass_lines=$(grep -i 'proxy_pass' /etc/nginx/nginx.conf)

    if [ -n "$proxy_pass_lines" ]; then
        log "[*] proxy_pass directives found in the configuration:"
        echo "$proxy_pass_lines" | while IFS= read -r line; do
            log "  $line"
        done
        log "[*] WARNING: proxy_pass directives are present. This may indicate potential security issues."
    else
        log "[*] 配置文件中未发现 proxy_passs配置"
    fi
    log_complete "Nginx配置文件检查完成"

    # 检测 SSH 公私钥文件
    log "[12.5] 开始检查SSH key 文件....."
    
    ssh_dir="/root/.ssh"
    if [ -d $ssh_dir ]; then
        log "[*] SSH directory: $ssh_dir"
        
        # 检查公钥文件
        if [ -f $ssh_dir/id_rsa.pub ]; then
            log "[*] Public key file: $ssh_dir/id_rsa.pub"
            cat $ssh_dir/id_rsa.pub | while IFS= read -r line; do
                log "  $line"
            done
        else
            log "[*] Public key file not found at $ssh_dir/id_rsa.pub."
        fi
        log_complete "SSH公钥文件检查完成"
        
        # 检查私钥文件
        if [ -f $ssh_dir/id_rsa ]; then
            log "[*] Private key file: $ssh_dir/id_rsa"
        else
            log "[*] Private key file not found at $ssh_dir/id_rsa."
        fi
    else
        log "[!!!] SSH目录未发现 $ssh_dir."
    fi
    log_complete "SSH公私钥文件检查完成"


    # 检测 SSH 配置文件
    log "[12.6] 开始检查ssh_config配置文件"
    # 检查是否允许空口令用户
    
    allow_empty_password=$(grep -i '^PermitEmptyPasswords' /etc/ssh/sshd_config | awk '{print $2}')
    if [ "$allow_empty_password" == "yes" ]; then
        log "WARNING: PermitEmptyPasswords is set to yes. This allows empty password authentication."
    else
        log "PermitEmptyPasswords未配置."
    fi
    log_complete "SSH配置文件检查完成"

    # 检查是否禁止 root 登录
    log "[12.7] 开始检查是否禁止 root 登录"
    if [[ "$line" =~ ^PermitRootLogin\ no$ ]]; then
        log "PermitRootLogin 未设置"
    elif [[ "$line" =~ ^PermitRootLogin\ yes$ ]]; then
        log_danger "PermitRootLogin配置了"
    fi
    log_complete "检查完成"

    # 检查是否启用公钥认证
    log "[12.8] 开始检查是否启用公钥认证"
    if [[ "$line" =~ ^PubkeyAuthentication\ yes$ ]]; then
        log "PubkeyAuthentication 未配置."
    elif [[ "$line" =~ ^PubkeyAuthentication\ no$ ]]; then
        log "PubkeyAuthentication 已配置."
    fi
    log_complete "是否启用公钥认证检查完成"

    # 检查是否启用 X11 转发
    log "[12.9] 开始检查是否启用 X11 转发"
    if [[ "$line" =~ ^X11Forwarding\ yes$ ]]; then
        log "X11Forwarding 未配置"
    elif [[ "$line" =~ ^X11Forwarding\ no$ ]]; then
        log "X11Forwarding 已配置."
    fi
    log_complete "是否启用 X11 转发检查完成"

    # 检查是否启用 AgentForwarding 
    log "[12.10] 开始检查是否启用 AgentForwarding"
    if [[ "$line" =~ ^AllowAgentForwarding\ yes$ ]]; then
        log "AllowAgentForwarding 未配置."
    elif [[ "$line" =~ ^AllowAgentForwarding\ no$ ]]; then
        log "AllowAgentForwarding 已配置."
    fi
    log_complete " AgentForwarding检查完成"

    # 检测环境变量配置
    log "【12.11】开始检查环境变量"
    env_files=("/etc/profile" "/etc/bashrc" "~/.bashrc")
    for env_file in "${env_files[@]}"; do
        if [ -f $env_file ]; then
            log "发现环境变量"
            cat $env_file | while IFS= read -r line; do
                log "  $line"
            done
        else
            log "环境变量未发现"
        fi
    done
    log_complete "环境变量检查完成 "
}


# 检测用户的 history 文件
log "[13] 开始检查用户的历史命令..."
check_user_history() {
    local user=$1
    local home_dir=$(getent passwd "$user" | cut -d: -f6)
    local history_file="$home_dir/.bash_history"

    if [ -f "$history_file" ]; then
        log "检查用户 $user 的历史命令文件: $history_file"
        
        # 读取历史命令
        while IFS= read -r command; do
            log "  $command"
            
            # 检查恶意命令
            if [[ "$command" =~ ^sudo.* ]] || \
               [[ "$command" =~ ^rm.* ]] || \
               [[ "$command" =~ ^wget.* ]] || \
               [[ "$command" =~ ^curl.* ]] || \
               [[ "$command" =~ ^nc.* ]] || \
               [[ "$command" =~ ^bash.* ]] || \
               [[ "$command" =~ ^python.* ]] || \
               [[ "$command" =~ ^perl.* ]] || \
               [[ "$command" =~ ^telnet.* ]] || \
               [[ "$command" =~ ^useradd.* ]] || \
               [[ "$command" =~ ^userdel.* ]] || \
               [[ "$command" =~ ^passwd.* ]] || \
               [[ "$command" =~ ^nmap.* ]] || \
               [[ "$command" =~ ^ssh.* ]] || \
               [[ "$command" =~ ^scp.* ]] || \
               [[ "$command" =~ ^ftp.* ]] || \
               [[ "$command" =~ ^tftp.* ]] || \
               [[ "$command" =~ ^openssl.* ]] || \
               [[ "$command" =~ ^netcat.* ]]; then
                log_danger "发现用户 $user 的潜在恶意命令: $command"
            fi
        done < "$history_file"
    else
        log_complete "用户 $user 未发现历史命令"
    fi
}

# 检测所有用户的 history 文件
check_all_user_histories() {
    log "[14] 开始检查所有用户的历史命令..."
    
    # 获取所有用户
    users=$(cut -d: -f1 /etc/passwd)
    
    for user in $users; do
        check_user_history "$user"
    done
    
    log "所有用户的历史命令检查完成"
}

# 定义关键文件列表
KEY_FILES=(
    "/usr/bin/awk"
    "/usr/bin/bash"
    "/usr/bin/cat"
    "/usr/bin/chattr"
    "/usr/bin/chmod"
    "/usr/bin/chown"
    "/usr/bin/cp"
    "/usr/bin/csh"
    "/usr/bin/curl"
    "/usr/bin/cut"
    "/usr/bin/date"
    "/usr/bin/df"
    "/usr/bin/diff"
    "/usr/bin/dirname"
    "/usr/bin/dmesg"
    "/usr/bin/du"
    "/usr/bin/echo"
    "/usr/bin/ed"
    "/usr/bin/egrep"
    "/usr/bin/env"
    "/usr/bin/fgrep"
    "/usr/bin/file"
    "/usr/bin/find"
    "/usr/bin/gawk"
    "/usr/bin/GET"
    "/usr/bin/grep"
    "/usr/bin/groups"
    "/usr/bin/head"
    "/usr/bin/id"
    "/usr/bin/ipcs"
    "/usr/bin/kill"
    "/usr/bin/killall"
    "/usr/bin/kmod"
    "/usr/bin/last"
    "/usr/bin/lastlog"
    "/usr/bin/ldd"
    "/usr/bin/less"
    "/usr/bin/locate"
    "/usr/bin/logger"
    "/usr/bin/login"
    "/usr/bin/ls"
    "/usr/bin/lsattr"
    "/usr/bin/lynx"
    "/usr/bin/mail"
    "/usr/bin/mailx"
    "/usr/bin/md5sum"
    "/usr/bin/mktemp"
    "/usr/bin/more"
    "/usr/bin/mount"
    "/usr/bin/mv"
    "/usr/bin/netstat"
    "/usr/bin/newgrp"
    "/usr/bin/numfmt"
    "/usr/bin/passwd"
    "/usr/bin/perl"
    "/usr/bin/pgrep"
    "/usr/bin/ping"
    "/usr/bin/pkill"
    "/usr/bin/ps"
    "/usr/bin/pstree"
    "/usr/bin/pwd"
    "/usr/bin/readlink"
    "/usr/bin/runcon"
    "/usr/bin/sed"
    "/usr/bin/sh"
    "/usr/bin/sha1sum"
    "/usr/bin/sha224sum"
    "/usr/bin/sha256sum"
    "/usr/bin/sha384sum"
    "/usr/bin/sha512sum"
    "/usr/bin/size"
    "/usr/bin/sort"
    "/usr/bin/ssh"
    "/usr/bin/stat"
    "/usr/bin/strace"
    "/usr/bin/strings"
    "/usr/bin/su"
    "/usr/bin/sudo"
    "/usr/bin/systemctl"
    "/usr/bin/tail"
    "/usr/bin/tcsh"
    "/usr/bin/telnet"
    "/usr/bin/test"
    "/usr/bin/top"
    "/usr/bin/touch"
    "/usr/bin/tr"
    "/usr/bin/uname"
    "/usr/bin/uniq"
    "/usr/bin/users"
    "/usr/bin/vmstat"
    "/usr/bin/w"
    "/usr/bin/watch"
    "/usr/bin/wc"
    "/usr/bin/wget"
    "/usr/bin/whatis"
    "/usr/bin/whereis"
    "/usr/bin/which"
    "/usr/bin/who"
    "/usr/bin/whoami"
    "/usr/lib/systemd/s"
    "/usr/local/bin/rkh"
    "/usr/sbin/adduser"
    "/usr/sbin/chkconfi"
    "/usr/sbin/chroot"
    "/usr/sbin/depmod"
    "/usr/sbin/fsck"
    "/usr/sbin/fuser"
    "/usr/sbin/groupadd"
    "/usr/sbin/groupdel"
    "/usr/sbin/groupmod"
    "/usr/sbin/grpck"
    "/usr/sbin/ifconfig"
    "/usr/sbin/ifdown"
    "/usr/sbin/ifup"
    "/usr/sbin/init"
    "/usr/sbin/insmod"
    "/usr/sbin/ip"
    "/usr/sbin/lsmod"
    "/usr/sbin/lsof"
    "/usr/sbin/modinfo"
    "/usr/sbin/modprobe"
    "/usr/sbin/nologin"
    "/usr/sbin/pwck"
    "/usr/sbin/rmmod"
    "/usr/sbin/route"
    "/usr/sbin/rsyslogd"
    "/usr/sbin/runlevel"
    "/usr/sbin/sestatus"
    "/usr/sbin/sshd"
    "/usr/sbin/sulogin"
    "/usr/sbin/sysctl"
    "/usr/sbin/tcpd"
    "/usr/sbin/useradd"
    "/usr/sbin/userdel"
    "/usr/sbin/usermod"
    "/usr/sbin/vipw"
)

# 利用md5sum检测文件完整性
check_filemd5() {
    log "[15] 开始使用 md5sum 检查关键文件完整性..."

    # 遍历每个关键文件并验证其完整性
    log "[15.1] 开始检查文件 MD5"
    for file in "${KEY_FILES[@]}"; do
        if [ -f "$file" ]; then
            current_md5=$(md5sum "$file" | awk '{print $1}')
            log "$file MD5: $current_md5"
        fi
    done
    log_complete "关键文件完整性检查完成"
}


# 检测已删除但仍被打开的文件
check_deleted_open_files() {
    log "[16] 检测已删除但仍被打开的文件..."
    deleted_files=$(find /proc/ -name exe 2>/dev/null | xargs ls -altr 2>/dev/null | grep deleted)
    
    if [ -z "$deleted_files" ]; then
        log "未发现已删除但仍被打开的文件"
    else
        log "发现已删除但仍被打开的文件:"
        echo "$deleted_files" | while read -r line; do
            log "$line"
            pid=$(echo "$line" | awk '{print $9}' | sed 's/\/proc\///' | sed 's/\/exe//')
  
            # 保存 /proc/<pid>/exe 文件
            exe_file="/proc/$pid/exe"
            if [ -f "$exe_file" ]; then
                target_file="${LOG_DIR}/exe_${pid}_${DATE}"
                cat "$exe_file" >> "$target_file"
            else
                log "文件 $exe_file 不存在"
            fi
        done
    fi
    log_complete "检查完成"
}


# 检测/var/log中的登录成功、登录失败、本机登录和新增用户
check_login_activity() {
    log "[17] 开始检查登录活动..."

    # 检测登录成功
    log "[17.1] 检查成功登录记录..."
    successful_logins=$(grep 'Accepted' /var/log/secure)
    if [ -n "$successful_logins" ]; then
        log "发现成功登录记录:"
        echo "$successful_logins" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "未发现成功登录记录"
    fi
    log_complete "检查完成"

    # 检测登录失败
    log "[17.2] 检查失败登录记录..."
    failed_logins=$(grep 'Failed' /var/log/secure)
    if [ -n "$failed_logins" ]; then
        log "发现失败登录记录:"
        echo "$failed_logins" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "未发现失败登录记录"
    fi
    log_complete "检查完成"

    # 检测本机登录
    log "[17.3] 检查本地登录记录..."
    local_logins=$(last | grep 'tty')
    if [ -n "$local_logins" ]; then
        log "发现本地登录记录:"
        echo "$local_logins" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "未发现本地登录记录"
    fi
    log_complete "检查完成"

    # 检测新增用户
    log "[17.4] 检查新增用户..."
    new_users=$(grep 'useradd' /var/log/secure)
    if [ -n "$new_users" ]; then
        log "发现新增用户:"
        echo "$new_users" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "未发现新增用户"
    fi
    log_complete "检查完成"

    # 检测 ZMODEM 传输
    log "[17.5] 检查ZMODEM传输记录..."
    zmodem_transfers=$(grep "ZMODEM:.*BPS" /var/log/messages* | awk -F '[]/]' '{print $0}' | sort | uniq)
    if [ -n "$zmodem_transfers" ]; then
        log "发现ZMODEM传输记录:"
        echo "$zmodem_transfers" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "未发现ZMODEM传输记录"
    fi
    log_complete "检查完成"

    # 检测使用的 DNS 服务器
    log "[17.6] 检查使用的DNS服务器..."

    log "[17.6] 检查使用的 DNS 服务器..."
    dns_servers=$(grep "using nameserver" /var/log/messages* | awk '{print $NF}' | awk -F# '{print $1}' | sort | uniq)
    if [ -n "$dns_servers" ]; then
        log "发现 DNS 服务器:"
        echo "$dns_servers" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "未发现 DNS 服务器"
    fi
    log_complete "检查完成"

    # 检测定时任务中的 wget 和 curl 命令
    log "[17.7] 检查 cron 任务中的 wget 或 curl 命令..."
    cron_tasks=$(grep -E "wget|curl" /var/log/cron* | sort | uniq)
    if [ -n "$cron_tasks" ]; then
        log "发现 cron 任务中使用 wget 或 curl:"
        echo "$cron_tasks" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "未发现 cron 任务中使用 wget 或 curl"
    fi
    log_complete "检查完成"


    # 检测软件安装情况
    log "[17.8] 检查已安装的软件..."
    installed_software=$(grep Installed /var/log/yum* | awk '{print $NF}' | sort | uniq)
    if [ -n "$installed_software" ]; then
        log "发现已安装的软件:"
        echo "$installed_software" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "未发现已安装的软件"
    fi
    log_complete "检查完成"

}

# 打包日志文件
backup_logs() {
    log "[18] 开始备份日志..."

    # 使用 zip 命令将 /var/log/ 目录下的日志文件打包
    zip -r $BACKUP_FILE /var/log/

    if [ $? -eq 0 ]; then
        log "日志备份成功完成。备份文件: $BACKUP_FILE"
    else
        log "日志备份失败"
    fi
}


# 检测 dmesg 日志中的安全相关事件
check_dmesg_security() {
    log "[19] 开始检查 dmesg 安全审计..."

    # 获取 dmesg 日志
    dmesg_output=$(dmesg)

    # 检测内核警告
    log "[19.1] 检查内核警告..."
    kernel_warnings=$(echo "$dmesg_output" | grep -i 'warning')
    if [ -n "$kernel_warnings" ]; then
        log "发现内核警告:"
        echo "$kernel_warnings" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "未发现内核警告"
    fi
    log_complete "检查完成"

    # 检测内核错误
    log "[19.2] 检查内核错误..."
    kernel_errors=$(echo "$dmesg_output" | grep -i 'error')
    if [ -n "$kernel_errors" ]; then
        log "发现内核错误:"
        echo "$kernel_errors" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "未发现内核错误"
    fi
    log_complete "检查完成"

    # 检测驱动程序问题
    log "[19.3] 检查驱动程序问题..."
    driver_issues=$(echo "$dmesg_output" | grep -i 'driver')
    if [ -n "$driver_issues" ]; then
        log "发现驱动程序问题:"
        echo "$driver_issues" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "未发现驱动程序问题"
    fi
    log_complete "检查完成"

    # 检测非法访问尝试
    log "[19.4] 检查非法访问尝试..."
    illegal_access=$(echo "$dmesg_output" | grep -i 'illegal')
    if [ -n "$illegal_access" ]; then
        log "发现非法访问尝试:"
        echo "$illegal_access" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "未发现非法访问尝试"
    fi

    # 检测安全相关的事件
    log "[19.5] 检查安全相关事件..."
    security_events=$(echo "$dmesg_output" | grep -iE 'security|audit|suspicious')
    if [ -n "$security_events" ]; then
        log "发现安全相关事件:"
        echo "$security_events" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "未发现安全相关事件"
    fi
    log_complete "检查完成"

    # 检测内存问题
    log "[19.6] 检查内存问题..."
    memory_issues=$(echo "$dmesg_output" | grep -iE 'memory|out of memory|oom')
    if [ -n "$memory_issues" ]; then
        log "发现内存问题:"
        echo "$memory_issues" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "未发现内存问题"
    fi

    # 检测网络问题
    log "[19.7] 检查网络问题..."
    network_issues=$(echo "$dmesg_output" | grep -iE 'network|eth|wlan|tcp|udp|ip')
    if [ -n "$network_issues" ]; then
        log "发现网络问题:"
        echo "$network_issues" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "未发现网络问题"
    fi
    log_complete "检查完成"

    # 检测硬件问题
    log "[19.8] 检查硬件问题..."
    hardware_issues=$(echo "$dmesg_output" | grep -iE 'hardware|device|firmware')
    if [ -n "$hardware_issues" ]; then
        log "发现硬件问题:"
        echo "$hardware_issues" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "未发现硬件问题"
    fi
    log_complete "检查完成"

    # 检测系统挂起或崩溃
    log "[19.9] 检查系统挂起或崩溃..."
    system_issues=$(echo "$dmesg_output" | grep -iE 'hang|crash|panic|reboot|shutdown')
    if [ -n "$system_issues" ]; then
        log "发现系统挂起或崩溃问题:"
        echo "$system_issues" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "未发现系统挂起或崩溃问题"
    fi
    log_complete "检查完成"
}


# 检测 lsmod 输出中的安全相关事件
check_lsmod_security() {
    log "[20] 开始检查 lsmod 安全审计..."

    # 获取 lsmod 输出
    lsmod_output=$(lsmod)

    # 记录所有加载的模块
    log "[20.1] 已加载的模块:"
    echo "$lsmod_output" | while IFS= read -r line; do
        log "  $line"
    done
    log_complete "检查完成"

    # 检测可疑的模块名称
    log "[20.2] 检查可疑的模块名称..."
    suspicious_modules=$(echo "$lsmod_output" | grep -iE 'rootkit|hack|malware|exploit|inject|hidden|backdoor')
    if [ -n "$suspicious_modules" ]; then
        log "发现可疑模块:"
        echo "$suspicious_modules" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "未发现可疑模块"
    fi
    log_complete "检查完成"

    # 检测加载的模块数量
    log "[20.3] 检查已加载模块数量..."
    module_count=$(echo "$lsmod_output" | wc -l)
    log "已加载模块数量: $module_count"

    # 检测模块大小
    log "[20.4] 检查模块大小..."
    large_modules=$(echo "$lsmod_output" | awk '{if ($2 > 1000000) print $0}')
    if [ -n "$large_modules" ]; then
        log "发现大型模块 大于1MB:"
        echo "$large_modules" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "未发现大型模块"
    fi
    log_complete "检查完成"

    # 检测模块依赖关系
    log "[20.5] 检查模块依赖关系..."
    echo "$lsmod_output" | tail -n +2 | while IFS= read -r line; do
        module_name=$(echo "$line" | awk '{print $1}')
        dependencies=$(echo "$line" | awk '{print $4}')
        if [ "$dependencies" != "-" ]; then
            log "模块 $module_name 的依赖项: $dependencies"
        fi
    done
    log_complete "检查完成"

    # 检测模块参数
    log "[20.6] 检查模块参数..."
    echo "$lsmod_output" | tail -n +2 | while IFS= read -r line; do
        module_name=$(echo "$line" | awk '{print $1}')
        parameters=$(modinfo -p $module_name 2>/dev/null)
        if [ -n "$parameters" ]; then
            log "模块 $module_name 的参数:"
            echo "$parameters" | while IFS= read -r param; do
                log "  $param"
            done
        fi
    done
    log_complete "检查完成"

    # 检测模块签名
    log "[20.7] 检查模块签名..."
    echo "$lsmod_output" | tail -n +2 | while IFS= read -r line; do
        module_name=$(echo "$line" | awk '{print $1}')
        signature=$(modinfo -F signer $module_name 2>/dev/null)
        if [ -n "$signature" ]; then
            log "模块 $module_name 由以下签名者签名: $signature"
        else
            log "模块 $module_name 未签名"
        fi
    done
    log_complete "检查完成"

    # 检测模块来源
    log "[20.8] 检查模块来源..."
    echo "$lsmod_output" | tail -n +2 | while IFS= read -r line; do
        module_name=$(echo "$line" | awk '{print $1}')
        source=$(modinfo -F filename $module_name 2>/dev/null)
        if [ -n "$source" ]; then
            log "模块 $module_name 来源: $source"
        else
            log "未找到模块 $module_name 的来源"
        fi
    done
    log_complete "检查完成"
}



# 检测已安装的软件
check_malware_software() {
    log "[21] 开始检查软件安装..."
    # 获取已安装的软件列表
    installed_packages=$(which dpkg >/dev/null 2>&1 && dpkg -l | awk '{print $2}' || ls -l /usr/bin)

    log "[21.1] 发现已安装的软件:"
    echo "$installed_packages" | while IFS= read -r package; do
        log "  $package"
    done

    log_complete "检查完成"

    # 检测恶意软件
    log "[21.2] 开始检测恶意软件..."
    # 定义恶意软件黑名单
    malware_blacklist=(
        "rootkit"
        "hack"
        "malware"
        "exploit"
        "inject"
        "hidden"
        "backdoor"
        "trojan"
        "virus"
        "worm"
        "spyware"
        "adware"
        "ransomware"
        "keylogger"
        "botnet"
        "miner"
        "cryptojacking"
        "ddos"
        "phishing"
        "shellcode"
        "kit"
        "kitteh"
        "mirai"
        "darkcomet"
        "netbus"
        "sub7"
        "gh0st"
        "njrat"
        "poisonivy"
        "zeus"
        "conficker"
        "cryptolocker"
        "locky"
        "wannacry"
        "petya"
        "notpetya"
        "emotet"
        "trickbot"
        "qakbot"
        "dridex"
        "gandcrab"
        "samSam"
        "cobaltstrike"
        "meterpreter"
        "nmap"
        "hydra"
        "sqlmap"
        "john"
        "hashcat"
        "metasploit"
        "msfconsole"
        "ncat"
        "netcat"
        "socat"
        "sshpass"
        "proftpd"
        "vsftpd"
        "openbsd-inetd"
        "inetd"
        "xinetd"
        "sshd"
        "dropbear"
    )

    # 检查已安装的软件是否在黑名单中
    for package in $(echo "$installed_packages"); do
        for malware in "${malware_blacklist[@]}"; do
            if [[ $package == *$malware* ]]; then
                log "发现恶意软件: $package"
            fi
        done
    done
    log_complete "检查完成"
}

# 针对使用的性能进行检测
check_performanc() {
    #检测磁盘使用情况
    log "[22] 开始检查磁盘使用情况..."
    disk_usage=$(df -h)
    log "[22.1] 磁盘使用情况:"
    echo "$disk_usage" | while IFS= read -r line; do
        log "  $line"
    done
    log "磁盘使用情况检查完成"

    # 检测 CPU 使用率
    log "[22.2] 开始检查CPU使用率..."
    cpu_usage=$(top -b -n 1 | grep "Cpu(s)")
    log "CPU使用率:"
    log "  $cpu_usage"
    log_complete "CPU使用率检查完成"

    # 检测内存使用情况
    log "[22.3] 开始检查内存使用情况..."
    memory_usage=$(free -m)
    log "内存使用情况:"
    echo "$memory_usage" | while IFS= read -r line; do
        log "  $line"
    done
    log_complete "内存使用情况检查完成"

    # 检测网络连接
    log "[22.4] 开始检查网络连接..."
    network_connections=$(ss -tuln)
    log "网络连接:"
    echo "$network_connections" | while IFS= read -r line; do
        log "  $line"
    done
    log_complete "网络连接检查完成"

    # 检测高 CPU 使用率的进程
    log "[22.5] 开始检查CPU使用率>50的进程..."
    high_cpu_processes=$(ps aux --sort=-%cpu | awk 'NR==1 || $3 >= 50 {print $0}')
    log "CPU使用率>50的进程:"
    echo "$high_cpu_processes" | while IFS= read -r line; do
        log "  $line"
    done
    log_complete "检查完成"

    # 检测高内存使用率的进程
    log "[22.6] 开始检查内存使用>=50%的进程..."
    high_memory_processes=$(ps aux --sort=-%mem | awk 'NR==1 || $4 >= 50 {print $0}')
    log "内存使用>=50%的进程:"
    echo "$high_memory_processes" | while IFS= read -r line; do
        log "  $line"
    done
    log_complete "检查完成"
}


#检测后门以及持久化
check_backdoor_persistence(){

    # 检测隐藏文件
    log "[23.1] 开始检测隐藏文件..."
    # 检查根目录及其子目录下的隐藏文件，排除 /var 和 /sys 目录
    hidden_files=$(find / -path /var -prune -o -path /sys -prune -o -name ".*" -type f 2>/dev/null)

    if [ -z "$hidden_files" ]; then
        log "未发现隐藏文件"
    else
        log "发现隐藏文件:"
        echo "$hidden_files" | while read -r file; do
            log "  $file"
        done
    fi
    log_complete "检查完成"

    # 检测具有a和i属性的文件
    log "[23.2]开始检测特殊属性文件..."

    # 检查根目录及其子目录下具有 a 和 i 属性的文件
    special_files=$(lsattr -R / 2>/dev/null | grep -- '-ia-')

    if [ -z "$special_files" ]; then
        log "未发现具有特殊属性 a 或 i 的文件"
    else
        log "发现具有特殊属性 a 或 i 的文件:"
        echo "$special_files" | while read -r file; do
            log "  $file"
        done
    fi

    log_complete "特殊属性文件检测完成"

   
    # 检测隐藏的 crontab 后门

    log "[23.3] 开始检测隐藏的 crontab 后门..."
    # 读取 /var/spool/cron/root 文件，使用 cat -A 查看隐藏字符
    log "使用 cat -A 读取 /var/spool/cron/root..."
    hidden_content=$(cat -A /var/spool/cron/root)

    if [ -n "$hidden_content" ]; then
        log "在 /var/spool/cron/root 中发现隐藏内容:"
        log "$hidden_content"
        log "可能存在隐藏的 crontab 后门"
    else
        log "在 /var/spool/cron/root 中未发现隐藏内容"
    fi

    log_complete "隐藏的 crontab 后门检测完成"


    # 检测端口复用情况
    log "[23.4] 开始检测端口复用..."

    listening_ports=$(netstat -anltp | grep 'LISTEN' | awk '{split($4, addr, ":"); print addr[2]}')

    # 检查每个端口的 PID
    while IFS= read -r port; do
        if [ -n "$port" ]; then
            # 使用 lsof 检查该端口是否有多个进程
            pid_count=$(lsof -i :$port | grep -v "/usr/bin" | awk 'NR>1 {print $1}' | sort | uniq | wc -l)

            if [ "$pid_count" -gt 1 ]; then
                log "端口 $port 被多个进程复用"
                # 获取具体 PID
                pids=$(lsof -i :$port | awk 'NR>1 {print $1}' | sort | uniq)
                log "使用端口 $port 的进程: $(echo "$pids" | tr '\n' ', ' | sed 's/,$//')"
            fi
        fi
    done <<< "$listening_ports"

    log_complete "端口复用检测完成"

}

#检测防火墙配置
check_firewall_iptables() {
    log "[24] 开始检查防火墙配置"
    # 检查 SELinux 状态
    selinux_status=$(sestatus)
    log "[24.1] SELinux 状态:"
    echo "$selinux_status" | while read -r line; do
        log "  $line"
    done

    # 检查 SELinux 配置文件
    log "[24.2] 开始检测 SELinux 配置..."
    selinux_config_file="/etc/selinux/config"
    if [ -f "$selinux_config_file" ]; then
        log "发现 SELinux 配置文件: $selinux_config_file"
        log "SELinux 配置:"
        while IFS='=' read -r key value; do
            if [[ "$key" =~ ^SELINUX|^SELINUXTYPE ]]; then
                log "  $key=$value"
            fi
        done < "$selinux_config_file"
    else
        log "未找到 SELinux 配置文件: $selinux_config_file"
    fi

    log_complete "SELinux 配置检测完成"


    # 检测 iptables 配置
    log "[24.3] 开始检测 iptables 配置..."

    # 检查 iptables 规则
    iptables_rules=$(iptables -L -v -n)
    log "iptables 规则:"
    echo "$iptables_rules" | while read -r line; do
        log "  $line"
    done
    log_complete "iptables 配置检测完成"

    # 检查 iptables 保存的规则文件
    log "[24.4] 开始检测 iptables 保存的规则文件"
    iptables_save_file="/etc/sysconfig/iptables"
    if [ -f "$iptables_save_file" ]; then
        log "发现 iptables 保存的规则文件: $iptables_save_file"
        log "iptables 保存的规则文件内容:"
        while read -r line; do
            log "  $line"
        done < "$iptables_save_file"
    else
        log "未找到 iptables 保存的规则文件: $iptables_save_file"
    fi

    log_complete "iptables 配置检测完成"


    # 检测恶意配置
    log "[24.5] Starting malicious configuration detection..."

    # 检查 SELinux 配置文件中的恶意配置
    selinux_config_file="/etc/selinux/config"
    if [ -f "$selinux_config_file" ]; then
        log "Checking for malicious SELinux configuration..."
        while IFS='=' read -r key value; do
            if [[ "$key" == "SELINUX" && "$value" == "permissive" || "$value" == "disabled" ]]; then
                log "  Warning: SELinux is set to permissive or disabled: $key=$value"
            fi
        done < "$selinux_config_file"
    fi
    log_complete "SELinux 配置检测完成"

    # 检查 iptables 规则中的恶意配置
    iptables_rules=$(iptables -L -v -n)
    log "[24.6] Checking for malicious iptables rules..."
    echo "$iptables_rules" | while read -r line; do
        if echo "$line" | grep -qE 'ACCEPT|DROP|REJECT' && ! echo "$line" | grep -qE 'lo|127\.0\.0\.1'; then
            log "  Warning: Suspicious iptables rule: $line"
        fi
    done

    log_complete "恶意配置检测完成"

}


# 检测反弹Shell
check_reversed_shell() {
    log "【25】开始检测反弹shell"
    # 获取所有ESTABLISHED连接并且文件描述符为 0u、1u 或 2u 的进程 PID
    pids=$(lsof -n | grep ESTABLISHED | grep -wE '0u|1u|2u' | awk '{print $2}' | uniq)

    # 检查可疑 PID 的文件描述符
    for pid in $pids; do
        fd_info=$(ls -al /proc/$pid/fd 2>/dev/null)
        if echo "$fd_info" | grep -q 'socket'; then
            log "Reversed shell detected for PID $pid"
        fi
    done
    log_complete "反弹shell检测完成"

    # 通过检测进程中的可疑操作来检测
    log "[13.2] 开始检查可疑进程和命令行参数..."
    suspicious_processes=$(ps aux | grep -E 'nc|netcat|bash -i|python -c|perl -e|ruby -e|ruby -rsocket|php -r|socat' | grep -v grep | awk '{print $2}')
    
    if [ -n "$suspicious_processes" ]; then
        log "Suspicious processes found:"
        echo "$suspicious_processes" | while read -r line; do
            log "  $line"
        done
    else
        log "未发现可疑进程和命令"
    fi
    log_complete "可疑进程和命令行参数检查完成"
}

# 检查库文件劫持
check_library_hijack() {
    log "【26】开始检查库文件劫持..."

    # 检查 LD_PRELOAD 环境变量
    log "[26.1] 检查LD_PRELOAD环境变量..."
    ld_preload_inject=$(echo $LD_PRELOAD)
    if [ -n "$ld_preload_inject" ]; then
        log "LD_PRELOAD设置为: $ld_preload_inject"
    else
        log "未设置LD_PRELOAD环境变量"
    fi
    log_complete "库文件劫持检查完成"


    # 检查/etc/ld.so.preload劫持
    log "[26.2] 开始检查/etc/ld.so.preload文件"
    preload_content=$(busybox cat /etc/ld.so.preload 2>/dev/null)
    if [ $? -ne 0 ]; then
        log "无法读取/etc/ld.so.preload"
    else
        log "检测到库文件劫持:"
        log "$preload_content"
    fi
    log_complete "/etc/ld.so.preload 文件检查完成"


    # 检测默认加载的动态库是否被篡改
    log "[26.3] 开始检查默认库文件变更..."

    # 执行 strace 命令并捕获输出
    output=$(strace -f -e trace=file /bin/whoami 2>&1 | grep 'access("[^"]*", R_OK)' | grep -oP 'access\("\K[^"]*')
    if [[ -z "$output" ]]; then
        log "未发现访问调用"
        return
    fi

    # 检查默认的动态库是否为/etc/ld.so.preload
    if echo "$output" | grep -q '/etc/ld.so.preload'; then
        log "默认动态库检查通过"
    else
        log "默认动态库已被篡改，发现可疑路径:"
        for path in $output; do
            log "可疑路径: $path"
        done
    fi

    log_complete "默认库文件检查完成"


    # 检查 /etc/ld.so.conf 文件
    log "[26.4] 开始检查/etc/ld.so.conf..."

    # 读取 /etc/ld.so.conf 文件内容
    content=$(cat /etc/ld.so.conf 2>/dev/null)

    if [[ -z "$content" ]]; then
        log "/etc/ld.so.conf为空或不存在"
        return
    fi
    log_complete "/etc/ld.so.conf文件检查完成"

    # 将内容按行分割
    IFS=$'\n' read -d '' -ra lines <<< "$content"

    # 定义常见系统目录
    common_dirs=("/lib" "/usr/lib" "/lib64" "/usr/lib64")

    # 初始化可疑路径和重复路径数组
    suspicious_paths=()
    duplicate_paths=()
    unique_paths=()

    for line in "${lines[@]}"; do
        # 跳过注释和空行
        if [[ -z "$line" || $line =~ ^# ]]; then
            continue
        fi

        # 检查路径是否包含可疑目录
        if echo "$line" | grep -qE '(/tmp|/home|/var/tmp)'; then
            suspicious_paths+=("$line")
            log "发现可疑路径: $line"
        fi

        # 检查路径是否重复
        if [[ " ${unique_paths[@]} " =~ " ${line} " ]]; then
            duplicate_paths+=("$line")
            log "发现重复路径: $line"
        else
            unique_paths+=("$line")
        fi

        # 检查路径是否在常见系统目录中
        if ! echo "${common_dirs[@]}" | grep -q "$line"; then
            log "发现未知路径: $line"
        fi
    done

    if [[ ${#suspicious_paths[@]} -eq 0 ]] && [[ ${#duplicate_paths[@]} -eq 0 ]]; then
        log "在/etc/ld.so.conf中未发现可疑或重复路径"
    fi

    log_complete "/etc/ld.so.conf检查完成"


    # 检查关键系统二进制文件的库依赖
    log "[26.5] 检查关键系统二进制文件的库依赖..."
    critical_binaries=(
        "/bin/ls" "/bin/ps" "/bin/netstat" "/usr/bin/who" "/usr/bin/top" "/usr/sbin/lsof"
        "/bin/cat" "/bin/chmod" "/bin/chown" "/bin/cp" "/bin/date" "/bin/df" "/bin/echo"
        "/bin/grep" "/bin/kill" "/bin/ln" "/bin/mkdir" "/bin/mv" "/bin/ping" "/bin/rm"
        "/bin/touch" "/sbin/ifconfig" "/sbin/ip" "/sbin/netstat" "/sbin/service" "/sbin/shutdown"
        "/usr/bin/curl" "/usr/bin/find" "/usr/bin/gawk" "/usr/bin/less" "/usr/bin/nmap"
        "/usr/bin/nc" "/usr/bin/ps" "/usr/bin/sudo" "/usr/bin/tar" "/usr/bin/wget"
    )
    for binary in "${critical_binaries[@]}"; do
        if [ -f "$binary" ]; then
            log "检查文件 $binary 的库依赖..."
            ldd $binary 2>/dev/null | tee -a $LOG_FILE
        else
            log_danger "二进制文件不存在: $binary"
        fi
    done

    log_complete "库文件劫持检查完成"
}


# 检查并安装busybox
check_and_install_busybox() {
    if ! command -v busybox &> /dev/null; then
        log "【27】开始安装busybox..."
        commands=(
            "wget https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/busybox-x86_64 -O /tmp/busybox-x86_64"
            "cp /tmp/busybox-x86_64 /usr/local/bin/busybox"
            "chmod +x /usr/local/bin/busybox"
        )

        # 执行命令并检查返回值
        for cmd in "${commands[@]}"; do
            if ! $cmd; then
                log "busybox安装失败"
                exit 1
            fi
        done

        log_complete "busybox安装成功"
    fi

}

# 检查并安装unhide
check_and_install_unhide() {
    if ! command -v unhide &> /dev/null; then
        log "【28】unhide未安装，正在安装..."
        yum install -y unhide
        if [[ $? -ne 0 ]]; then
            log "unhide安装失败"
            exit 1
        fi
        log_complete "unhide安装成功"
    fi
}


# 检测隐藏进程
detect_hidden_process() {
    log "【29】开始检测隐藏进程..."
    hidden_pids=$(unhide proc | grep -oP 'Found HIDDEN PID: \K\d+')
    if [[ -n "$hidden_pids" ]]; then
        log "发现隐藏进程: $hidden_pids"
    else
        log "未发现隐藏进程"
        return 1
    fi
    log_complete "隐藏进程检测完成"
}

# 检测进程挂载
detect_process_mount() {
    log "【30】开始检测进程挂载..."
    # 获取 /proc/ 下的挂载点
    mounts=$(cat /proc/mounts | grep '/proc/' | grep -oP '/proc/\K\d+')
    if [[ -n "$mounts" ]]; then
        # 运行 netstat -anltp，提取出 PID
        netstat_pids=$(netstat -anltp | awk '{print $7}' | awk -F'/' '{print $1}' | grep -oE '[0-9]+' | sort -nu)
        if [[ -n "$netstat_pids" ]]; then
            for pid1 in $mounts; do
                if ! echo "$netstat_pids" | grep -q "^$pid1$"; then
                    log "通过进程挂载发现PID $pid1"
                    umount -l /proc/$pid1
                    log "PID $pid1 已被响应并可以正常查看"
                fi
            done
        fi
    else
        log "未发现进程挂载"
    fi
    log_complete "进程挂载检测完成"
}

# 检测库文件劫持
detect_library_hijacking() {
    log "【31】开始检测库文件劫持..."

    # 检查 LD_PRELOAD 环境变量
    ld_preload_inject=$(echo $LD_PRELOAD)
    if [ -n "$ld_preload_inject" ]; then
        log "LD_PRELOAD设置为: $ld_preload_inject"
    fi
    log_complete "LD_PRELOAD检查完成"

    # 检查/etc/ld.so.preload劫持
    preload_content=$(busybox cat /etc/ld.so.preload 2>/dev/null)
    if [ $? -ne 0 ]; then
        log "无法读取/etc/ld.so.preload"
    else
        log "检测到库文件劫持:$preload_content"
    fi
    log_complete "/etc/ld.so.preload检查完成"

    #  检查默认的动态库是否为/etc/ld.so.preload
    output=$(strace -f -e trace=file /bin/whoami 2>&1 | grep 'access("[^"]*", R_OK)' | grep -oP 'access\("\K[^"]*' | grep -q '/etc/ld.so.preload')
    if [[ -n "$output" ]]; then
        for path in $output; do
            log "默认动态库已被篡改，发现可疑路径:$path"
        done
    fi
    log_complete "库文件劫持检测完成"
}

# 检测 Diamorphine rootkit
detect_diamorphine_rootkit() {
    log "【32】开始检测Diamorphine rootkit..."

    # 检查安装后相关文件与日志是否存在
    find_output=$(busybox find / -name diamorphine 2>/dev/null)
    dmesg_output=$(dmesg | grep diamorphine 2>/dev/null)
    sys_module_output=$(ls -l /sys/module/diamorphine 2>/dev/null) 
    if [[ -n "$find_output" ]] || [[ -n "$dmesg_output" ]] || [[ -n "$sys_module_output" ]]; then
        log "发现Diamorphine Rootkit!"
        # 检查Diamorphine使用默认参数-31来隐藏进程
        pids1=$(netstat -anltp | grep -oP '\b\d+/\S+' | cut -d/ -f1 | sort -u)

        # 将 PID 存储到数组中
        IFS=$'\n' read -r -d '' -a pid1_array <<< "$pids1"

        # 检测隐藏进程
        hidden_pids=$(unhide proc | grep -oP 'Found HIDDEN PID: \K\d+')
        if [[ -n "$hidden_pids" ]]; then
            IFS=$'\n' read -r -d '' -a pid2_array <<< "$hidden_pids"
            for pid2 in "${pid2_array[@]}"; do
                kill -31 $pid2 2>/dev/null
                # 再次获取 PID 列表
                pids3=$(netstat -anltp | grep -oP '\b\d+/\S+' | cut -d/ -f1 | sort -u)
                IFS=$'\n' read -r -d '' -a pid3_array <<< "$pids3"

                # 检查 PID 是否在新的列表中
                if [[ " ${pid3_array[*]} " =~ " $pid2 " ]] && ! [[ " ${pid1_array[*]} " =~ " $pid2 " ]]; then
                    log "检测到LKM Rootkit: PID $pid2"
                    log "PID $pid2 已被响应并可以正常查看"
                fi
            done
        fi
    fi
    log_complete "Diamorphine rootkit检测完成"
}

# 进度显示函数
show_progress() {
    local current=$1
    local total=$2
    local prefix=$3
    local width=50
    local percentage=$((current * 100 / total))
    local completed=$((width * current / total))
    local remaining=$((width - completed))
    
    printf "\r${prefix} [%-${width}s] %d%%" "$(printf "%${completed}s" | tr ' ' '#')$(printf "%${remaining}s" | tr ' ' '-')" "$percentage"
    if [ "$current" -eq "$total" ]; then
        echo
    fi
}

print_section_header() {
    local title=$1
    echo -e "\n${PURPLE}============== $title ==============${NC}"
}

# 全局计数器
declare -i TOTAL_CHECKS=0
declare -i PASSED_CHECKS=0
declare -i WARNING_CHECKS=0
declare -i DANGER_CHECKS=0

# 在每个检查函数末尾添加计数
count_check_result() {
    local status=$1
    ((TOTAL_CHECKS++))
    case "$status" in
        "pass") ((PASSED_CHECKS++));;
        "warning") ((WARNING_CHECKS++));;
        "danger") ((DANGER_CHECKS++));;
    esac
}

# 在main函数结束时显示统计
print_summary() {
    echo -e "\n${PURPLE}============== 检查结果统计 ==============${NC}"
    echo -e "总检查项: ${TOTAL_CHECKS}"
    echo -e "${GREEN}通过项: ${PASSED_CHECKS}${NC}"
    echo -e "${YELLOW}警告项: ${WARNING_CHECKS}${NC}"
    echo -e "${RED}危险项: ${DANGER_CHECKS}${NC}"
    
    # 计算得分
    local score=$((100 * PASSED_CHECKS / TOTAL_CHECKS))
    echo -e "\n系统安全得分: ${score}/100"
}

# 主函数，按顺序执行所有检查
main() {
    # 设置错误处理
    set +e  # 临时禁用错误退出
    
    log "开始进行Linux主机安全检查..."
    check_systeminfo
    check_arp_spoofing
    check_open_port
    check_connections
    check_interface
    check_account
    check_startup
    check_crontab
    check_routing_forwarded
    check_processes
    check_config
    check_all_user_histories
    check_filemd5
    check_deleted_open_files
    check_login_activity
    check_dmesg_security
    check_lsmod_security
    check_malware_software
    check_performanc
    check_and_install_busybox
    check_and_install_unhide
    check_backdoor_persistence
    check_firewall_iptables
    check_reversed_shell
    check_library_hijack
    detect_hidden_process
    detect_process_mount
    detect_library_hijacking
    detect_diamorphine_rootkit
    backup_logs
 
    log "安全检查完成。详细结果请查看日志文件:$LOG_FILE"
    log "危险项记录请查看:$DANGER_FILE"
    log "日志备份文件:$BACKUP_FILE"
    
    set -e  # 重新启用错误退出
}


# 运行主函数
main
