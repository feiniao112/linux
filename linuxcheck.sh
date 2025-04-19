#!/bin/bash
echo "Version:2.1"
echo "Author:飞鸟"
echo "Create Date:2019-02-19"
echo "Update Date:2025-04-19"


# 添加全局错误处理
set -e  # 遇到错误立即退出
trap 'echo "Error occurred at line $LINENO"; exit 1' ERR

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
    echo -e "${BLUE}[${timestamp}]${NC} $1" | tee -a $LOG_FILE
}

log_danger() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "${RED}[${timestamp}] [危险]${NC} $1" | tee -a $DANGER_FILE
}

log_warning() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "${YELLOW}[${timestamp}] [警告]${NC} $1" | tee -a $LOG_FILE
}

log_success() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "${GREEN}[${timestamp}] [正常]${NC} $1" | tee -a $LOG_FILE
}

# 检查是否为 root 用户
if [ "$(whoami)" != "root" ]; then
    echo "The security check must use the root account, otherwise some items cannot be checked"
    exit 1
fi

# 添加系统检测函数
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    elif [ -f /etc/redhat-release ]; then
        OS="centos"
    else
        OS="unknown"
    fi
    echo $OS
}

# 添加包管理器兼容性函数
install_package() {
    local package_name=$1
    local os_type=$(detect_os)
    
    case $os_type in
        "ubuntu"|"debian")
            apt-get update && apt-get install -y $package_name
            ;;
        "centos"|"rhel")
            yum install -y $package_name
            ;;
        *)
            log "不支持的操作系统类型"
            return 1
            ;;
    esac
}

# 修改检查系统基本信息函数
check_systeminfo() {
    local ret=0
    local os_type=$(detect_os)
    {
        log "[1] Starting check_systeminfo ..."
        # 检测 IP 地址
        log "[1.1] Starting IP Address check..."
        ip_addresses=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}')
        if [ -z "$ip_addresses" ]; then
            log "No IP addresses found."
        else
            log "IP Addresses:"
            echo "$ip_addresses" | while IFS= read -r line; do
                log "  $line"
            done
        fi
        log "[*] IP Address check completed. [*]"

        # 检测操作系统版本
        log "[1.2] Starting OS Version check..."
        case $os_type in
            "ubuntu"|"debian")
                os_version=$(cat /etc/os-release | grep "PRETTY_NAME" | cut -d'"' -f2)
                ;;
            "centos"|"rhel")
                if [ -f /etc/redhat-release ]; then
                    os_version=$(cat /etc/redhat-release)
                else
                    os_version=$(cat /etc/os-release | grep "PRETTY_NAME" | cut -d'"' -f2)
                fi
                ;;
            *)
                os_version="Unknown OS"
                ;;
        esac
        
        if [ -z "$os_version" ]; then
            log "Failed to retrieve OS version."
        else
            log "OS Version: $os_version"
        fi
        log "[*] OS Version check completed. [*]"
    } || ret=$?
    
    if [ $ret -ne 0 ]; then
        log_danger "System info check failed with error code $ret"
        return $ret
    fi
}

# 检测 ARP 表以及ARP攻击
check_arp_spoofing() {
    log "[2] Starting check_arp_spoofing"
    log "[2.1] Starting ARP Table check..."
    arp_table=$(arp -a)
    if [ -z "$arp_table" ]; then
        log "No ARP entries found."
    else
        log "ARP Table:"
        echo "$arp_table" | while IFS= read -r line; do
            log "  $line"
        done
    fi
    log "[*] ARP Table check completed. [*]"

    # 检测ARP攻击
    log "[2.2] Starting ARP Spoofing detection..."
    arp_entries=$(arp -a | awk '{print $4}' | sort | uniq -c | sort -nr)
    if [ -z "$arp_entries" ]; then
        log "No ARP entries found."
    else
        log "ARP Entries Count:"
        echo "$arp_entries" | while IFS= read -r line; do
            count=$(echo $line | awk '{print $1}')
            mac=$(echo $line | awk '{print $2}')
            if [ "$count" -gt 1 ]; then
                log "Potential ARP Spoofing detected: MAC address $mac appears $count times."
            else
                log "  $line"
            fi
        done
    fi
    log "[*] ARP Spoofing detection completed. [*]"
}


check_open_port() {
    log "[3] Starting check_open_port"
    # Check Open TCP Port and Process
    log "[3.1] Checking for open TCP ports and processes....."
    tcpopen=$(netstat -anltp | grep LISTEN | awk '{print $4,$7}' | sed 's/:/ /g' | awk '{print $2,$3}' | sed 's/\// /g' | awk '{printf "%-20s%-10s\n", $1, $NF}' | sort -n | uniq)
    if [ -n "$tcpopen" ]; then
        log "The server has the following open TCP ports and corresponding processes:"
        echo "$tcpopen" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "No TCP ports are open on the system"
    fi


    # Check TCP ports open to LAN or Internet
    log "[3.2] Starting Check TCP ports open to LAN or Internet"
    tcpports=$(netstat -anltp | grep LISTEN | awk '{print $4}' | egrep "(0.0.0.0|:::)" | awk -F: '{print $NF}' | sort -n | uniq)
    if [ -n "$tcpports" ]; then
        log "The following TCP ports are open to the local network or internet:"
        for port in $tcpports; do
            log "  $port"
        done
    else
        log "No TCP ports are open to the local network or internet."
    fi

    # Detect potentially dangerous tcp ports
    log "[3.3] Starting detect potentially dangerous tcp ports"
    dangerous_ports="21 22 23 25 135 137 138 139 143 3389 8080"
    open_ports=$(netstat -anltp | grep LISTEN | awk '{print $4}' | egrep "(0.0.0.0|:::)" | awk -F: '{print $NF}' | sort -n | uniq)
    if [ -n "$open_ports" ]; then
        for port in $open_ports; do
            if [[ " ${dangerous_ports[@]} " =~ " ${port} " ]]; then
                log_danger "Dangerous TCP port $port is open to the local network or internet."
            fi
        done
    fi


    # check open UDP port
    log "[3.4] Starting check for open UDP ports and processes....."
    udpopen=$(netstat -anlup | awk '{print $4,$7}' | grep : | sed 's/:/ /g' | awk '{print $2,$3}' | sed 's/\// /g' | awk '{printf "%-20s%-10s\n", $1, $NF}' | sort -n | uniq)
    if [ -n "$udpopen" ]; then
        log "The server has the following open UDP ports and corresponding processes:"
        echo "$udpopen" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "[*] No UDP ports are open on the system"
    fi


    # Detect UDP ports open to LAN or Internet
    log "[3.5] Detect UDP ports open to LAN or Internet"
    udpports=$(netstat -anlup | grep LISTEN | awk '{print $4}' | egrep "(0.0.0.0|:::)" | awk -F: '{print $NF}' | sort -n | uniq)
    if [ -n "$udpports" ]; then
        log "The following UDP ports are open to the local network or internet:"
        for port in $udpports; do
            log "  $port"
        done
    else
        log "[*] No UDP ports are open to the local network or internet."
    fi

    #Detect potentially dangerous udp ports
    log "[3.6]Starting Detect potentially dangerous udp ports"
    dangerous_ports="137 138 161 162 500 1900 5353"
    open_ports=$(netstat -anlup | awk '{print $4}' | egrep "(0.0.0.0|:::)" | awk -F: '{print $NF}' | sort -n | uniq)
    if [ -n "$open_ports" ]; then
        for port in $open_ports; do
            if [[ " ${dangerous_ports[@]} " =~ " ${port} " ]]; then
                log_danger "[!!!] Dangerous UDP port $port is open to the local network or internet."
            fi
        done
    fi
}


# 检测活动的网络连接
check_connections() {
    log "[4] Checking for active network connections....."
    active_connections=$(netstat -anp | grep -E 'tcp|udp' | grep ESTABLISHED)
    if [ -n "$active_connections" ]; then
        log "The server has the following active network connections:"
        echo "$active_connections" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "[*] No active network connections found."
    fi
}


# 查询威胁情报

# API 密钥
APIKEY=""

check_ip_threatbook() {
    log "[5] Starting Check IP threatbook"
    ips=$(netstat -anltp | awk '{print $5}' | sed 's/:.*//' | grep -E '[0-9]' | grep -vwE "0.0.0.0|127.0.0.1" | uniq)
    for ip in $ips; do
        log "Querying ThreatBook for IP: $ip"
        response=$(curl -s -X GET "https://api.threatbook.cn/v3/scene/ip_reputation?apikey=${APIKEY}&resource=$ip")   
        formatted_response=$(echo "$response" | jq .)
        log "Response for IP $ip:"
        log "$formatted_response"
    done
}


# 检测网卡基本信息
check_interface() {
    log "[6] Starting check_interface"
    log "[6.1] Checking network interface information....."
    interfaces=$(ip link show | grep -oP '^\d+: \K\w+')
    if [ -n "$interfaces" ]; then
        for interface in $interfaces; do
            log "Interface: $interface"
            log "  IP Information:"
            ip addr show $interface 2>/dev/null | while read -r line; do
                log "  $line"
            done
            
            # 获取默认网关
            default_gateway=$(ip route | grep default | grep -oP 'via \K\S+' || echo "Not found")
            log "  Default Gateway: $default_gateway"
            
            # 获取 DNS 服务器
            if [ -f "/etc/resolv.conf" ]; then
                dns_servers=$(grep nameserver /etc/resolv.conf | awk '{print $2}')
                log "  DNS Servers: $dns_servers"
            else
                log "  DNS configuration file not found"
            fi
            
            # 获取 MAC 地址
            mac_address=$(ip link show $interface | grep -oP 'link/ether \K\S+' || echo "Not found")
            log "  MAC Address: $mac_address"
            
            # 检测网卡是否处于混杂模式
            if ip link show $interface | grep -q PROMISC; then
                log_danger "Interface $interface is in promiscuous mode"
            else
                log_success "Interface $interface is not in promiscuous mode"
            fi
            
            # 检测网卡是否处于监听模式
            if command -v iw >/dev/null 2>&1; then
                if iw dev $interface info 2>/dev/null | grep -q "type monitor"; then
                    log_danger "Interface $interface is in monitor mode"
                else
                    log_success "Interface $interface is not in monitor mode"
                fi
            else
                log "iw command not found, skipping monitor mode check"
            fi
            
            # 获取传输速率
            if command -v ethtool >/dev/null 2>&1; then
                speed=$(ethtool $interface 2>/dev/null | grep -oP 'Speed: \K\S+' || echo "Unknown")
                log "  Speed: $speed"
            else
                log "ethtool command not found, skipping speed check"
            fi
            
            # 获取错误计数器
            if command -v ethtool >/dev/null 2>&1; then
                errors=$(ethtool -S $interface 2>/dev/null | grep -E 'rx_errors|tx_errors|rx_dropped|tx_dropped' || echo "No errors found")
                log "  Error Counters:"
                echo "$errors" | while read -r line; do
                    log "    $line"
                done
            fi
        done
    else
        log_warning "No network interfaces found"
    fi
    
    log "[6] Interface check completed"
}


check_account() {
    log "[7] Starting check_account"
    # 检查空口令用户
    log "[7.1] Starting Empty Password check..."
    empty_password_users=$(sudo awk -F: '($2 == "") {print $1}' /etc/shadow)
    if [ -z "$empty_password_users" ]; then
        log "No users with empty passwords found."
    else
        log_danger "Users with empty passwords found: $empty_password_users"
    fi
    log "[*] Empty Password check completed."


    # 检查空口令且可以登录的用户
    log "[7.2] Starting Empty Password and Login Users check..."
    
    # 获取空口令用户
    empty_password_users=$(sudo awk -F: '($2 == "") {print $1}' /etc/shadow)
    
    if [ -z "$empty_password_users" ]; then
        log "No users with empty passwords found."
    else
        log "Users with empty passwords found:"
        echo "$empty_password_users" | while IFS= read -r user; do
            # 检查用户是否可以登录
            login_shell=$(grep "^$user:" /etc/passwd | cut -d: -f7)
            if [ "$login_shell" != "/sbin/nologin" ] && [ "$login_shell" != "/usr/sbin/nologin" ]; then
                log_danger "User with empty password and can login: $user, Shell: $login_shell"
            else
                log "User with empty password but cannot login: $user, Shell: $login_shell"
            fi
        done
    fi
    
    log "[7.3] Empty Password and Login Users check completed."
    # 检查超级用户
    log "Starting Superuser check..."
    superusers=$(awk -F: '($3 == 0) && ($1 != "root") {print $1}' /etc/passwd)
    if [ -z "$superusers" ]; then
        log "No superusers found."
    else
        log_danger "Superusers found: $superusers"
    fi
    log "Superuser check completed."


    log "[7.4] Starting Cloned Accounts check..."    
    # 检查克隆账号-具有相同用户名的账号
    log "Checking for accounts with the same username..."
    duplicate_usernames=$(cut -d: -f1 /etc/passwd | sort | uniq -d)
    if [ -z "$duplicate_usernames" ]; then
        log "No accounts with the same username found."
    else
        log_danger "Accounts with the same username found: $duplicate_usernames"
    fi

    # 检查克隆账号-具有相同 UID 的账号
    log "[7.5] Checking for accounts with the same UID..."
    duplicate_uids=$(cut -d: -f3 /etc/passwd | sort | uniq -d)
    if [ -z "$duplicate_uids" ]; then
        log "No accounts with the same UID found."
    else
        log_danger "Accounts with the same UID found: $duplicate_uids"
        for uid in $duplicate_uids; do
            log_danger "Accounts with UID $uid: $(grep ":$uid:" /etc/passwd)"
        done
    fi

    log "Cloned Accounts check completed."


    # 检查可登录用户
    log "[7.6] Starting login user detection..."
    valid_shells=$(getent passwd | awk -F: '($7 !~ /^(\/usr)?\/sbin\/nologin$|\/bin\/false$|\/usr\/lib\/gdm3\/gdm\-x\-session$/) {print $1}')

    # 检查这些用户的密码是否未被锁定
    while IFS= read -r user; do
        password_entry=$(sudo getent shadow "$user")
        if [[ -n "$password_entry" ]]; then
            password=$(echo "$password_entry" | cut -d: -f2)
            if ! echo "$password" | grep -qE '^\!|^\*'; then
                log "User $user is a valid login user."
            fi
        fi
    done <<< "$valid_shells"

    log "Login user detection completed."


    # 检查非系统用户
    log "[7.7] Starting Non-System Users check..."
    non_system_users=$(awk -F: '($3 >= 1000) {print $1, $3, $7}' /etc/passwd)
    if [ -z "$non_system_users" ]; then
        log "No non-system users found."
    else
        log "Non-system users found:"
        echo "$non_system_users" | while IFS=' ' read -r user uid shell; do
            log "$user"
        done
    fi
    log "[*] Non-System Users check completed."
}


# 修改系统特定路径变量
get_system_paths() {
    local os_type=$(detect_os)
    case $os_type in
        "ubuntu"|"debian")
            IPTABLES_SAVE="/etc/iptables/rules.v4"
            SYSLOG_PATH="/var/log/syslog"
            ;;
        "centos"|"rhel")
            IPTABLES_SAVE="/etc/sysconfig/iptables"
            SYSLOG_PATH="/var/log/messages"
            ;;
        *)
            IPTABLES_SAVE="/etc/sysconfig/iptables"
            SYSLOG_PATH="/var/log/messages"
            ;;
    esac
}

# 修改检测软件安装情况函数
check_installed_software() {
    local os_type=$(detect_os)
    log "[17.8] Checking installed software..."
    
    case $os_type in
        "ubuntu"|"debian")
            installed_software=$(grep " install " /var/log/dpkg.log | awk '{print $4}' | sort | uniq)
            ;;
        "centos"|"rhel")
            installed_software=$(grep Installed /var/log/yum.log | awk '{print $NF}' | sort | uniq)
            ;;
        *)
            installed_software=""
            ;;
    esac

    if [ -n "$installed_software" ]; then
        log "Installed software found:"
        echo "$installed_software" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "No installed software found or log not available."
    fi
}

# 修改检查系统启动项函数
check_startup() {
    log "[8] Starting check_startup"
    local os_type=$(detect_os)

    log "[8.1] Checking system startup items....."
    
    # 检查 Systemd 服务
    if command -v systemctl &> /dev/null; then
        systemd_services=$(systemctl list-unit-files --state=enabled --type=service | awk 'NR>1 {print $1}')
        if [ -n "$systemd_services" ]; then
            log "[*] Systemd Enabled services:"
            echo "$systemd_services" | while IFS= read -r line; do
                log "  $line"
            done
        else
            log "[*] No enabled Systemd services found."
        fi
    fi
    
    # 检查 /etc/rc.local
    log "[8.2] Checking /etc/rc.local"
    if [ -f /etc/rc.local ]; then
        rc_local_content=$(cat /etc/rc.local)
        if [ -n "$rc_local_content" ]; then
            log "[*] /etc/rc.local content:"
            echo "$rc_local_content" | while IFS= read -r line; do
                log "  $line"
            done
        else
            log "[*] /etc/rc.local is empty."
        fi
    else
        log "[*] /etc/rc.local does not exist."
    fi
    
    # 检查启动管理工具
    case $os_type in
        "ubuntu"|"debian")
            if command -v update-rc.d &> /dev/null; then
                log "[8.3] Checking update-rc.d managed services..."
                services=$(ls /etc/init.d/)
                for service in $services; do
                    if [ -x "/etc/init.d/$service" ]; then
                        log "  $service"
                    fi
                done
            fi
            ;;
        "centos"|"rhel")
            if command -v chkconfig &> /dev/null; then
                log "[8.4] Checking chkconfig managed services..."
                chkconfig_items=$(chkconfig --list | grep -E ":on|启用|开" | awk '{print $1}')
                if [ -n "$chkconfig_items" ]; then
                    log "[*] chkconfig managed startup items:"
                    echo "$chkconfig_items" | while IFS= read -r line; do
                        log "  $line"
                    done
                else
                    log "[*] No chkconfig managed startup items found."
                fi
            fi
            ;;
    esac
}

# 修改检测登录活动函数
check_login_activity() {
    log "[17] Starting login activity audit..."
    local os_type=$(detect_os)
    local auth_log
    
    case $os_type in
        "ubuntu"|"debian")
            auth_log="/var/log/auth.log"
            ;;
        "centos"|"rhel")
            auth_log="/var/log/secure"
            ;;
        *)
            auth_log="/var/log/secure"
            ;;
    esac

    # 检测登录成功
    log "[17.1] Checking successful logins..."
    successful_logins=$(grep 'Accepted' $auth_log)
    if [ -n "$successful_logins" ]; then
        log "Successful logins found:"
        echo "$successful_logins" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "No successful logins found."
    fi

    # 检测登录失败
    log "[17.2] Checking failed logins..."
    failed_logins=$(grep 'Failed' $auth_log)
    if [ -n "$failed_logins" ]; then
        log "Failed logins found:"
        echo "$failed_logins" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "No failed logins found."
    fi

    # 检测本机登录
    log "[17.3] Checking local logins..."
    local_logins=$(last | grep 'tty')
    if [ -n "$local_logins" ]; then
        log "Local logins found:"
        echo "$local_logins" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "No local logins found."
    fi

    # 检测新增用户
    log "[17.4] Checking new users..."
    new_users=$(grep 'useradd' /var/log/secure)
    if [ -n "$new_users" ]; then
        log "New users found:"
        echo "$new_users" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "No new users found."
    fi

    # 检测 ZMODEM 传输
    log "[17.5] Checking ZMODEM transfers..."
    zmodem_transfers=$(grep "ZMODEM:.*BPS" /var/log/messages* | awk -F '[]/]' '{print $0}' | sort | uniq)
    if [ -n "$zmodem_transfers" ]; then
        log "ZMODEM transfers found:"
        echo "$zmodem_transfers" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "No ZMODEM transfers found."
    fi


    # 检测使用的 DNS 服务器

    log "[17.6] Checking used DNS servers..."
    dns_servers=$(grep "using nameserver" /var/log/messages* | awk '{print $NF}' | awk -F# '{print $1}' | sort | uniq)
    if [ -n "$dns_servers" ]; then
        log "DNS servers found:"
        echo "$dns_servers" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "No DNS servers found."
    fi


    # 检测定时任务中的 wget 和 curl 命令
    log "[17.7] Checking cron tasks with wget or curl..."
    cron_tasks=$(grep -E "wget|curl" /var/log/cron* | sort | uniq)
    if [ -n "$cron_tasks" ]; then
        log "Cron tasks with wget or curl found:"
        echo "$cron_tasks" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "No cron tasks with wget or curl found."
    fi


    # 检测软件安装情况
    log "[17.8] Checking installed software..."
    installed_software=$(grep Installed /var/log/yum* | awk '{print $NF}' | sort | uniq)
    if [ -n "$installed_software" ]; then
        log "Installed software found:"
        echo "$installed_software" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "No installed software found."
    fi


    log "Login activity audit completed."
}

# 打包日志文件
backup_logs() {
    log "[18] Starting log backup..."

    # 使用 zip 命令将 /var/log/ 目录下的日志文件打包
    zip -r $BACKUP_FILE /var/log/

    if [ $? -eq 0 ]; then
        log "Log backup completed successfully. Backup file: $BACKUP_FILE"
    else
        log "Log backup failed."
    fi
}


# 检测 dmesg 日志中的安全相关事件
check_dmesg_security() {
    log "[19] Starting dmesg security audit..."

    # 获取 dmesg 日志
    dmesg_output=$(dmesg)

    # 检测内核警告
    log "[19.1] Checking kernel warnings..."
    kernel_warnings=$(echo "$dmesg_output" | grep -i 'warning')
    if [ -n "$kernel_warnings" ]; then
        log "Kernel warnings found:"
        echo "$kernel_warnings" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "No kernel warnings found."
    fi

    # 检测内核错误
    log "[19.2] Checking kernel errors..."
    kernel_errors=$(echo "$dmesg_output" | grep -i 'error')
    if [ -n "$kernel_errors" ]; then
        log "Kernel errors found:"
        echo "$kernel_errors" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "No kernel errors found."
    fi

    # 检测驱动程序问题
    log "[19.3] Checking driver issues..."
    driver_issues=$(echo "$dmesg_output" | grep -i 'driver')
    if [ -n "$driver_issues" ]; then
        log "Driver issues found:"
        echo "$driver_issues" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "No driver issues found."
    fi

    # 检测非法访问尝试
    log "[19.4] Checking illegal access attempts..."
    illegal_access=$(echo "$dmesg_output" | grep -i 'illegal')
    if [ -n "$illegal_access" ]; then
        log "Illegal access attempts found:"
        echo "$illegal_access" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "No illegal access attempts found."
    fi

    # 检测安全相关的事件
    log "[19.5] Checking security-related events..."
    security_events=$(echo "$dmesg_output" | grep -iE 'security|audit|suspicious')
    if [ -n "$security_events" ]; then
        log "Security-related events found:"
        echo "$security_events" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "No security-related events found."
    fi

    # 检测内存问题
    log "[19.6] Checking memory issues..."
    memory_issues=$(echo "$dmesg_output" | grep -iE 'memory|out of memory|oom')
    if [ -n "$memory_issues" ]; then
        log "Memory issues found:"
        echo "$memory_issues" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "No memory issues found."
    fi

    # 检测网络问题
    log "[19.7] Checking network issues..."
    network_issues=$(echo "$dmesg_output" | grep -iE 'network|eth|wlan|tcp|udp|ip')
    if [ -n "$network_issues" ]; then
        log "Network issues found:"
        echo "$network_issues" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "No network issues found."
    fi

    # 检测硬件问题
    log "[19.8] Checking hardware issues..."
    hardware_issues=$(echo "$dmesg_output" | grep -iE 'hardware|device|firmware')
    if [ -n "$hardware_issues" ]; then
        log "Hardware issues found:"
        echo "$hardware_issues" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "No hardware issues found."
    fi

    # 检测系统挂起或崩溃
    log "[19.9] Checking system hang or crash..."
    system_issues=$(echo "$dmesg_output" | grep -iE 'hang|crash|panic|reboot|shutdown')
    if [ -n "$system_issues" ]; then
        log "System hang or crash issues found:"
        echo "$system_issues" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "No system hang or crash issues found."
    fi

    log "Dmesg security audit completed."
}


# 检测 lsmod 输出中的安全相关事件
check_lsmod_security() {
    log "[20] Starting lsmod security audit..."

    # 获取 lsmod 输出
    lsmod_output=$(lsmod)

    # 记录所有加载的模块
    log "[20.1] Loaded modules:"
    echo "$lsmod_output" | while IFS= read -r line; do
        log "  $line"
    done

    # 检测可疑的模块名称
    log "[20.2] Checking suspicious module names..."
    suspicious_modules=$(echo "$lsmod_output" | grep -iE 'rootkit|hack|malware|exploit|inject|hidden|backdoor')
    if [ -n "$suspicious_modules" ]; then
        log "Suspicious modules found:"
        echo "$suspicious_modules" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "No suspicious modules found."
    fi

    # 检测加载的模块数量
    log "[20.3] Checking number of loaded modules..."
    module_count=$(echo "$lsmod_output" | wc -l)
    log "Number of loaded modules: $module_count"

    # 检测模块大小
    log "[20.4] Checking module sizes..."
    large_modules=$(echo "$lsmod_output" | awk '{if ($2 > 1000000) print $0}')
    if [ -n "$large_modules" ]; then
        log "Large modules found (size > 1MB):"
        echo "$large_modules" | while IFS= read -r line; do
            log "  $line"
        done
    else
        log "No large modules found."
    fi

    # 检测模块依赖关系
    log "[20.5] Checking module dependencies..."
    echo "$lsmod_output" | tail -n +2 | while IFS= read -r line; do
        module_name=$(echo "$line" | awk '{print $1}')
        dependencies=$(echo "$line" | awk '{print $4}')
        if [ "$dependencies" != "-" ]; then
            log "Module $module_name has dependencies: $dependencies"
        fi
    done

    # 检测模块参数
    log "[20.6] Checking module parameters..."
    echo "$lsmod_output" | tail -n +2 | while IFS= read -r line; do
        module_name=$(echo "$line" | awk '{print $1}')
        parameters=$(modinfo -p $module_name 2>/dev/null)
        if [ -n "$parameters" ]; then
            log "Module $module_name parameters:"
            echo "$parameters" | while IFS= read -r param; do
                log "  $param"
            done
        fi
    done

    # 检测模块签名
    log "[20.7] Checking module signatures..."
    echo "$lsmod_output" | tail -n +2 | while IFS= read -r line; do
        module_name=$(echo "$line" | awk '{print $1}')
        signature=$(modinfo -F signer $module_name 2>/dev/null)
        if [ -n "$signature" ]; then
            log "Module $module_name is signed by: $signature"
        else
            log "Module $module_name is not signed."
        fi
    done

    # 检测模块来源
    log "[20.8] Checking module sources..."
    echo "$lsmod_output" | tail -n +2 | while IFS= read -r line; do
        module_name=$(echo "$line" | awk '{print $1}')
        source=$(modinfo -F filename $module_name 2>/dev/null)
        if [ -n "$source" ]; then
            log "Module $module_name source: $source"
        else
            log "Module $module_name source not found."
        fi
    done


    log "Lsmod security audit completed."
}



# 检测已安装的软件
check_malware_software() {
    log "[21] Starting software installation audit..."
    # 获取已安装的软件列表
    installed_packages=$(which dpkg >/dev/null 2>&1 && dpkg -l | awk '{print $2}' || ls -l /usr/bin)

    log "[21.1] Installed software found:"
    echo "$installed_packages" | while IFS= read -r package; do
        log "  $package"
    done

    log "Software installation audit completed."

    # 检测恶意软件
    log "[21.2] Starting malware detection..."
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
                log "Malware detected: $package"
            fi
        done
    done

    log "Malware detection completed."
}

# 针对使用的性能进行检测
check_performanc() {

    #检测磁盘使用情况
    log "[22] Starting disk usage check..."
    disk_usage=$(df -h)
    log "[22.1] Disk usage:"
    echo "$disk_usage" | while IFS= read -r line; do
        log "  $line"
    done
    log "Disk usage check completed."


    # 检测 CPU 使用率
    log "[22.2] Starting CPU usage check..."
    cpu_usage=$(top -b -n 1 | grep "Cpu(s)")
    log "CPU usage:"
    log "  $cpu_usage"
    log "CPU usage check completed."

    # 检测内存使用情况
    log "[22.3] Starting memory usage check..."
    memory_usage=$(free -m)
    log "Memory usage:"
    echo "$memory_usage" | while IFS= read -r line; do
        log "  $line"
    done
    log "Memory usage check completed."


    # 检测网络连接
    log "[22.4] Starting network connections check..."
    network_connections=$(ss -tuln)
    log "Network connections:"
    echo "$network_connections" | while IFS= read -r line; do
        log "  $line"
    done
    log "Network connections check completed."


    # 检测高 CPU 使用率的进程
    log "[22.5] Starting high CPU usage processes check..."
    high_cpu_processes=$(ps aux --sort=-%cpu | awk 'NR==1 || $3 >= 50 {print $0}')
    log "High CPU usage processes (Top 10):"
    echo "$high_cpu_processes" | while IFS= read -r line; do
        log "  $line"
    done
    log "High CPU usage processes check completed."


    # 检测高内存使用率的进程
    log "[22.6] Starting high memory usage processes check..."
    high_memory_processes=$(ps aux --sort=-%mem | awk 'NR==1 || $4 >= 50 {print $0}')
    log "High memory usage processes (Top 10):"
    echo "$high_memory_processes" | while IFS= read -r line; do
        log "  $line"
    done
    log "High memory usage processes check completed."
}


#检测后门以及持久化
check_backdoor_persistence(){

    # 检测隐藏文件
    log "[23.1] Starting hidden files detection..."
    # 检查根目录及其子目录下的隐藏文件，排除 /var 和 /sys 目录
    hidden_files=$(find / -path /var -prune -o -path /sys -prune -o -name ".*" -type f 2>/dev/null)

    if [ -z "$hidden_files" ]; then
        log "No hidden files found."
    else
        log "Hidden files found:"
        echo "$hidden_files" | while read -r file; do
            log "  $file"
        done
    fi

    log "Hidden files detection completed."


    # 检测具有a和i属性的文件
    log "[23.2]Starting special attributes detection..."

    # 检查根目录及其子目录下具有 a 和 i 属性的文件
    special_files=$(lsattr -R / 2>/dev/null | grep -- '-ia-')

    if [ -z "$special_files" ]; then
        log "No files with special attributes (a or i) found."
    else
        log "Files with special attributes (a or i) found:"
        echo "$special_files" | while read -r file; do
            log "  $file"
        done
    fi

    log "Special attributes detection completed."

   
    # 检测隐藏的 crontab 后门

    log "[23.3] Starting crontab backdoor detection..."
    # 读取 /var/spool/cron/root 文件，使用 cat -A 查看隐藏字符
    log "Reading /var/spool/cron/root with cat -A..."
    hidden_content=$(cat -A /var/spool/cron/root)

    if [ -n "$hidden_content" ]; then
        log "Hidden content found in /var/spool/cron/root:"
        log "$hidden_content"
        log "This may indicate a hidden crontab backdoor."
    else
        log "No hidden content found in /var/spool/cron/root."
    fi

    log "Crontab backdoor detection completed."


    # 检测端口复用情况
    log "[23.4] Starting port reuse detection..."

    listening_ports=$(netstat -anltp | grep 'LISTEN' | awk '{split($4, addr, ":"); print addr[2]}')

    # 检查每个端口的 PID
    while IFS= read -r port; do
        if [ -n "$port" ]; then
            # 使用 lsof 检查该端口是否有多个进程
            pid_count=$(lsof -i :$port | grep -v "/usr/bin" | awk 'NR>1 {print $1}' | sort | uniq | wc -l)

            if [ "$pid_count" -gt 1 ]; then
                log "Port $port is reused by multiple processes."
                # 获取具体 PID
                pids=$(lsof -i :$port | awk 'NR>1 {print $1}' | sort | uniq)
                log "Processes using port $port: $(echo "$pids" | tr '\n' ', ' | sed 's/,$//')"
            fi
        fi
    done <<< "$listening_ports"

    log "Port reuse detection completed."

}

#检测防火墙配置
check_firewall_iptables() {
    local os_type=$(detect_os)
    
    # 检查防火墙状态
    log "[24.0] Checking firewall status..."
    case $os_type in
        "ubuntu"|"debian")
            if command -v ufw &> /dev/null; then
                ufw_status=$(ufw status)
                log "UFW Status:"
                echo "$ufw_status" | while read -r line; do
                    log "  $line"
                done
            else
                log "UFW is not installed"
            fi
            ;;
        "centos"|"rhel")
            if command -v firewall-cmd &> /dev/null; then
                firewalld_status=$(firewall-cmd --state)
                log "FirewallD Status: $firewalld_status"
                if [ "$firewalld_status" = "running" ]; then
                    zones=$(firewall-cmd --list-all-zones)
                    log "FirewallD Zones:"
                    echo "$zones" | while read -r line; do
                        log "  $line"
                    done
                fi
            else
                log "FirewallD is not installed"
            fi
            ;;
    esac

    # 检查 SELinux 状态
    if command -v sestatus &> /dev/null; then
        selinux_status=$(sestatus)
        log "[24.1] SELinux status:"
        echo "$selinux_status" | while read -r line; do
            log "  $line"
        done
    else
        log "[24.1] SELinux is not installed"
    fi

    # 检查 SELinux 配置文件
    log "[24.2] Starting SELinux configuration detection..."
    selinux_config_file="/etc/selinux/config"
    if [ -f "$selinux_config_file" ]; then
        log "SELinux configuration file found: $selinux_config_file"
        log "SELinux configuration:"
        while IFS='=' read -r key value; do
            if [[ "$key" =~ ^SELINUX|^SELINUXTYPE ]]; then
                log "  $key=$value"
            fi
        done < "$selinux_config_file"
    else
        log "SELinux configuration file not found: $selinux_config_file"
    fi

    log "SELinux configuration detection completed."


    # 检测 iptables 配置
    log "[24.3] Starting iptables configuration detection..."

    # 检查 iptables 规则
    iptables_rules=$(iptables -L -v -n)
    log "iptables rules:"
    echo "$iptables_rules" | while read -r line; do
        log "  $line"
    done

    # 检查 iptables 保存的规则文件
    log "[24.4] Starting check_iptables"
    iptables_save_file="/etc/sysconfig/iptables"
    if [ -f "$iptables_save_file" ]; then
        log "iptables save file found: $iptables_save_file"
        log "iptables save file content:"
        while read -r line; do
            log "  $line"
        done < "$iptables_save_file"
    else
        log "iptables save file not found: $iptables_save_file"
    fi

    log "iptables configuration detection completed."


    # 检测恶意配置
    log "[12.5] Starting malicious configuration detection..."

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

    # 检查 iptables 规则中的恶意配置
    iptables_rules=$(iptables -L -v -n)
    log "[12.6] Checking for malicious iptables rules..."
    echo "$iptables_rules" | while read -r line; do
        if echo "$line" | grep -qE 'ACCEPT|DROP|REJECT' && ! echo "$line" | grep -qE 'lo|127\.0\.0\.1'; then
            log "  Warning: Suspicious iptables rule: $line"
        fi
    done

    log "Malicious configuration detection completed."

}


# 检测反弹Shell
check_reversed_shell() {
    log "[13] Starting reversed shell detection..."

    # 获取所有ESTABLISHED连接并且文件描述符为 0u、1u 或 2u 的进程 PID
    log "[13.1] Starting check File_Descrition"
    pids=$(lsof -n | grep ESTABLISHED | grep -wE '0u|1u|2u' | awk '{print $2}' | uniq)

    # 检查可疑 PID 的文件描述符
    for pid in $pids; do
        fd_info=$(ls -al /proc/$pid/fd 2>/dev/null)
        if echo "$fd_info" | grep -q 'socket'; then
            log "Reversed shell detected for PID $pid"
        fi
    done

    # 通过检测进程中的可疑操作来检测
    log "[13.2] Checking suspicious processes and command-line arguments..."
    suspicious_processes=$(ps aux | grep -E 'nc|netcat|bash -i|python -c|perl -e|ruby -e|ruby -rsocket|php -r|socat' | grep -v grep | awk '{print $2}')
    
    if [ -n "$suspicious_processes" ]; then
        log "Suspicious processes found:"
        echo "$suspicious_processes" | while read -r line; do
            log "  $line"
        done
    else
        log "No Reversed shell found."
    fi

    log "Reversed shell detection completed."
}

# 检查库文件劫持
check_library_hijack() {
    log "[14] Starting Library Hijack check..."

    # 检查 LD_PRELOAD 环境变量
    log "[14.1] Checking LD_PRELOAD environment variable..."
    ld_preload_inject=$(echo $LD_PRELOAD)
    if [ -n "$ld_preload_inject" ]; then
        log "LD_PRELOAD is set to: $ld_preload_inject"
    else
        log "No LD_PRELOAD environment variable set."
    fi


    # 检查/etc/ld.so.preload劫持
    log "[14.2] Checking /etc/ld.so.preload..."
    preload_content=$(busybox cat /etc/ld.so.preload 2>/dev/null)
    if [ $? -ne 0 ]; then
        log "Failed to read /etc/ld.so.preload."
    else
        log "Library hijacking detected:"
        log "$preload_content"
    fi


    # 检测默认加载的动态库是否被篡改
    log "【14.3】Starting default library change check..."

    # 执行 strace 命令并捕获输出
    output=$(strace -f -e trace=file /bin/whoami 2>&1 | grep 'access("[^"]*", R_OK)' | grep -oP 'access\("\K[^"]*')
    if [[ -z "$output" ]]; then
        log "No access calls found."
        return
    fi

    # 检查默认的动态库是否为/etc/ld.so.preload
    if echo "$output" | grep -q '/etc/ld.so.preload'; then
        log "Default dynamic library check passed."
    else
        log "Default dynamic library has been tampered with. Suspicious paths found:"
        for path in $output; do
            log "Suspicious path: $path"
        done
    fi

    log "Default library check completed."


    # 检查 /etc/ld.so.conf 文件
    log "【14.4】Starting /etc/ld.so.conf detection..."

    # 读取 /etc/ld.so.conf 文件内容
    content=$(cat /etc/ld.so.conf 2>/dev/null)

    if [[ -z "$content" ]]; then
        log "/etc/ld.so.conf is empty or does not exist."
        echo "/etc/ld.so.conf is empty or does not exist."
        return
    fi

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
            log "Suspicious path found: $line"
            echo "Suspicious path found: $line"
        fi

        # 检查路径是否重复
        if [[ " ${unique_paths[@]} " =~ " ${line} " ]]; then
            duplicate_paths+=("$line")
            log "Duplicate path found: $line"
            echo "Duplicate path found: $line"
        else
            unique_paths+=("$line")
        fi

        # 检查路径是否在常见系统目录中
        if ! echo "${common_dirs[@]}" | grep -q "$line"; then
            log "Unknown path found: $line"
            echo "Unknown path found: $line"
        fi
    done

    if [[ ${#suspicious_paths[@]} -eq 0 ]] && [[ ${#duplicate_paths[@]} -eq 0 ]]; then
        log "No suspicious or duplicate paths found in /etc/ld.so.conf."
        echo "No suspicious or duplicate paths found in /etc/ld.so.conf."
    fi

    log "/etc/ld.so.conf detection completed."


    # 检查关键系统二进制文件的库依赖
    log "【14.5】Checking library dependencies of critical system binaries..."
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
            log "Checking library dependencies for $binary..."
            ldd $binary 2>/dev/null | tee -a $LOG_FILE
        else
            log_danger "Binary does not exist: $binary"
        fi
    done

    log "Library Hijack check completed."
}


# 检查并安装busybox
check_and_install_busybox() {
    if ! command -v busybox &> /dev/null; then
        commands=(
            "wget https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/busybox-x86_64 -O /tmp/busybox-x86_64"
            "cp /tmp/busybox-x86_64 /usr/local/bin/busybox"
            "chmod +x /usr/local/bin/busybox"
        )

        # 执行命令并检查返回值
        for cmd in "${commands[@]}"; do
            if ! $cmd; then
                echo "Failed to install busybox"
                exit 1
            fi
        done

        echo "busybox installed successfully"
    fi
}

# 修改检查并安装unhide函数
check_and_install_unhide() {
    if ! command -v unhide &> /dev/null; then
        log "unhide is not installed. Installing unhide..."
        install_package unhide
        if [[ $? -ne 0 ]]; then
            log "Failed to install unhide."
            exit 1
        fi
        log "unhide installed successfully."
    fi
}


# 检测隐藏进程
detect_hidden_process() {
    hidden_pids=$(unhide proc | grep -oP 'Found HIDDEN PID: \K\d+')
    if [[ -n "$hidden_pids" ]]; then
        log "Hidden process found: $hidden_pids"
    else
        log "No hidden process found."
        return 1
    fi
}

# 检测进程挂载
detect_process_mount() {
    log "[!!!]Detecting process mount..."
    # 获取 /proc/ 下的挂载点
    mounts=$(cat /proc/mounts | grep '/proc/' | grep -oP '/proc/\K\d+')
    if [[ -n "$mounts" ]]; then
        # 运行 netstat -anltp，提取出 PID
        netstat_pids=$(netstat -anltp | awk '{print $7}' | awk -F'/' '{print $1}' | grep -oE '[0-9]+' | sort -nu)
        if [[ -n "$netstat_pids" ]]; then
            for pid1 in $mounts; do
                if ! echo "$netstat_pids" | grep -q "^$pid1$"; then
                    log "PID $pid1 is Found by Process Mount !!!"
                    umount -l /proc/$pid1
                    log "PID $pid1 has been response and can be seen normally"
                fi
            done
        fi
    else
        log "Not Found process mount"
    fi
}

# 检测库文件劫持
detect_library_hijacking() {
    log "[!!!]Detecting Library Hijack..."

    # 检查 LD_PRELOAD 环境变量
    ld_preload_inject=$(echo $LD_PRELOAD)
    if [ -n "$ld_preload_inject" ]; then
        log "LD_PRELOAD is set to: $ld_preload_inject"
    fi

    # 检查/etc/ld.so.preload劫持
    preload_content=$(busybox cat /etc/ld.so.preload 2>/dev/null)
    if [ $? -ne 0 ]; then
        log "Failed to read /etc/ld.so.preload."
    else
        log "Library hijacking detected:$preload_content"
    fi

    #  检查默认的动态库是否为/etc/ld.so.preload
    output=$(strace -f -e trace=file /bin/whoami 2>&1 | grep 'access("[^"]*", R_OK)' | grep -oP 'access\("\K[^"]*' | grep -q '/etc/ld.so.preload')
    if [[ -n "$output" ]]; then
        for path in $output; do
            log "Default dynamic library has been tampered with. Suspicious paths found:$path"
        done
    fi

}

# 检测 Diamorphine rootkit
detect_diamorphine_rootkit() {
    log "[!!!]Detecting Diamorphine rootkit..."

    # 检查安装后相关文件与日志是否存在
    find_output=$(busybox find / -name diamorphine 2>/dev/null)
    dmesg_output=$(dmesg | grep diamorphine 2>/dev/null)
    sys_module_output=$(ls -l /sys/module/diamorphine 2>/dev/null) 
    if [[ -n "$find_output" ]] || [[ -n "$dmesg_output" ]] || [[ -n "$sys_module_output" ]]; then
        log "Found Diamorphine Rootkit!"
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
                    log "LKM Rootkit detected: PID $pid2"
                    log "PID $pid2 has been response and can be seen normally"
                fi
            done
        fi

        # 检查隐藏模块diamorphin
        sys_module_output=$(ls -l /sys/module/diamorphine 2>/dev/null)
        if [[ -n "$sys_module_output" ]]; then
            log "Diamorphine module detected by /sys/module/diamorphin"
        fi

        # 检查Diamorphine是否隐藏文件MAGIC_PREFIX "diamorphine_secret"
        # 创建测试文件
        test_file="diamorphine_secretx12ci"
        echo "test" > $test_file

        ls_output=$(ls -al | grep diamorphine_secretx12ci 2>/dev/null)
        if [[ -z "$ls_output" ]]; then
            cat_output=$(cat $test_file 2>/dev/null)
            if [[ "$cat_output" == "test" ]]; then
                log "Diamorphine Hidden file detected."
            fi
        fi

        # 清理测试文件
        rm -f diamorphine_secretx12ci
    else
        log "Not Found Diamorphine Rootkit"
    fi
}

# 并行执行检查任务
check_parallel() {
    check_systeminfo &
    check_arp_spoofing &
    check_open_port &
    wait
}

# 使用更高效的文件查找方法
find_suspicious_files() {
    # 使用-prune避免遍历不必要的目录
    find / -path /proc -prune -o -path /sys -prune -o -type f -name ".*" 2>/dev/null
}

# 添加文件完整性校验
verify_script_integrity() {
    local SCRIPT_HASH="预先计算的脚本哈希值"
    local current_hash=$(sha256sum "$0" | cut -d' ' -f1)
    if [ "$current_hash" != "$SCRIPT_HASH" ]; then
        echo "脚本文件可能被篡改！"
        exit 1
    fi
}

# 添加敏感信息保护
protect_sensitive_info() {
    chmod 600 "$LOG_FILE"
    chmod 600 "$DANGER_FILE"
}

# 将配置项移至单独的配置文件
CONFIG_FILE="/etc/security_check.conf"

load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    else
        log_danger "配置文件不存在：$CONFIG_FILE"
        exit 1
    fi
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
    
    log "开始全面Linux安全检查..."
    
    echo -e "\n${PURPLE}============== 基础环境检查 ==============${NC}"
    check_systeminfo
    
    echo -e "\n${PURPLE}============== 网络安全检查 ==============${NC}"
    check_arp_spoofing
    check_open_port
    check_connections
    check_interface
    
    echo -e "\n${PURPLE}============== 系统安全检查 ==============${NC}"
    check_account
    check_startup
    check_crontab
    check_routing_forwarded
    check_processes
    
    echo -e "\n${PURPLE}============== 配置安全检查 ==============${NC}"
    check_config
    
    echo -e "\n${PURPLE}============== 用户历史检查 ==============${NC}"
    check_all_user_histories
    
    echo -e "\n${PURPLE}============== 文件安全检查 ==============${NC}"
    check_filemd5
    check_deleted_open_files
    
    echo -e "\n${PURPLE}============== 日志安全检查 ==============${NC}"
    check_login_activity
    check_dmesg_security
    check_lsmod_security
    
    echo -e "\n${PURPLE}============== 恶意软件检查 ==============${NC}"
    check_malware_software
    check_performanc
    
    echo -e "\n${PURPLE}============== 后门检查 ==============${NC}"
    check_backdoor_persistence
    check_firewall_iptables
    check_reversed_shell
    check_library_hijack
    
    echo -e "\n${PURPLE}============== 备份日志 ==============${NC}"
    backup_logs
    
    log "安全检查完成。详细结果请查看日志文件：$LOG_FILE"
    log "危险项记录请查看：$DANGER_FILE"
    log "日志备份文件：$BACKUP_FILE"
    
    set -e  # 重新启用错误退出
}

# 运行主函数
main

# 添加辅助函数
isEmptyString() {
    local -r string="${1}"
    [[ -z "$string" ]]
}

removeEmptyLines() {
    local -r content="${1}"
    echo -e "${content}" | sed '/^[[:space:]]*$/d'
}

# 修复表格输出函数
print_table() {
    local delimiter="${1}"
    local data="${2}"

    # 如果数据为空则返回
    if isEmptyString "$data"; then
        return
    fi

    # 计算行数
    local numberOfLines
    numberOfLines=$(echo "$data" | wc -l)

    if [ "$numberOfLines" -gt 0 ]; then
        local table=""
        local i=1

        # 处理每一行
        while [ $i -le "$numberOfLines" ]; do
            local line
            line=$(echo "$data" | sed "${i}q;d")

            # 计算列数
            local numberOfColumns
            numberOfColumns=$(echo "$line" | awk -F"$delimiter" '{print NF}')

            # 添加表头分隔符
            if [ $i -eq 1 ]; then
                local header=""
                for ((j=1; j<=numberOfColumns; j++)); do
                    header="${header}+---"
                done
                table="${table}${header}+\n"
            fi

            # 添加数据行
            local row="|"
            for ((j=1; j<=numberOfColumns; j++)); do
                local cell
                cell=$(echo "$line" | cut -d"$delimiter" -f$j)
                row="${row} ${cell} |"
            done
            table="${table}${row}\n"

            # 添加底部分隔符
            if [ $i -eq 1 ] || [ $i -eq "$numberOfLines" ]; then
                local separator=""
                for ((j=1; j<=numberOfColumns; j++)); do
                    separator="${separator}+---"
                done
                table="${table}${separator}+\n"
            fi

            ((i++))
        done

        # 输出表格
        echo -e "$table"
    fi
}
