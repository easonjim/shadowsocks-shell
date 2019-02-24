#!/bin/bash
# 
# shadowsocks-libev install shell 

# defind environment 
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# Current folder
cur_dir=`pwd`

libsodium_file="libsodium-1.0.16"
libsodium_url="https://github.com/jedisct1/libsodium/releases/download/1.0.16/libsodium-1.0.16.tar.gz"

mbedtls_file="mbedtls-2.13.0"
mbedtls_url="https://tls.mbed.org/download/mbedtls-2.13.0-gpl.tgz"

# Stream Ciphers
ciphers=(
aes-256-gcm
aes-192-gcm
aes-128-gcm
aes-256-ctr
aes-192-ctr
aes-128-ctr
aes-256-cfb
aes-192-cfb
aes-128-cfb
camellia-128-cfb
camellia-192-cfb
camellia-256-cfb
xchacha20-ietf-poly1305
chacha20-ietf-poly1305
chacha20-ietf
chacha20
salsa20
rc4-md5
)
# Color
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

# Make sure only root can run our script
check_root(){
    [[ $EUID -ne 0 ]] && echo -e "[${red}Error${plain}] This script must be run as root!" && exit 1
}

# Disable selinux
disable_selinux(){
    if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

get_ip(){
    local IP=$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipv4.icanhazip.com )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipinfo.io/ip )
    [ ! -z ${IP} ] && echo ${IP} || echo
}

get_ipv6(){
    local ipv6=$(wget -qO- -t1 -T2 ipv6.icanhazip.com)
    if [ -z ${ipv6} ]; then
        return 1
    else
        return 0
    fi
}

get_char(){
    SAVEDSTTY=`stty -g`
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2> /dev/null
    stty -raw
    stty echo
    stty $SAVEDSTTY
}

get_latest_version(){
    ver=$(wget --no-check-certificate -qO- https://api.github.com/repos/shadowsocks/shadowsocks-libev/releases/latest | grep 'tag_name' | cut -d\" -f4)
    [ -z ${ver} ] && echo "Error: Get shadowsocks-libev latest version failed" && exit 1
    shadowsocks_libev_ver="shadowsocks-libev-$(echo ${ver} | sed -e 's/^[a-zA-Z]//g')"
    download_link="https://github.com/shadowsocks/shadowsocks-libev/releases/download/${ver}/${shadowsocks_libev_ver}.tar.gz"
}

check_installed(){
    if [ "$(command -v "$1")" ]; then
        return 0
    else
        return 1
    fi
}

check_version(){
    check_installed "ss-server"
    if [ $? -eq 0 ]; then
        installed_ver=$(ss-server -h | grep shadowsocks-libev | cut -d' ' -f2)
        get_latest_version
        latest_ver=$(echo ${ver} | sed -e 's/^[a-zA-Z]//g')
        if [ "${latest_ver}" == "${installed_ver}" ]; then
            return 0
        else
            return 1
        fi
    else
        return 2
    fi
}

print_info(){
    clear
    echo "#############################################################"
    echo "# Install shadowsocks-libev server for CentOS 6 or 7        #"
    echo "#############################################################"
    echo
}

# Check system
check_sys(){
    local checkType=$1
    local value=$2

    local release=''
    local systemPackage=''

    if [[ -f /etc/redhat-release ]]; then
        release="centos"
        systemPackage="yum"
    elif grep -Eqi "debian|raspbian" /etc/issue; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /etc/issue; then
        release="ubuntu"
        systemPackage="apt"
    elif grep -Eqi "centos|red hat|redhat" /etc/issue; then
        release="centos"
        systemPackage="yum"
    elif grep -Eqi "debian|raspbian" /proc/version; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /proc/version; then
        release="ubuntu"
        systemPackage="apt"
    elif grep -Eqi "centos|red hat|redhat" /proc/version; then
        release="centos"
        systemPackage="yum"
    fi

    if [[ "${checkType}" == "sysRelease" ]]; then
        if [ "${value}" == "${release}" ]; then
            return 0
        else
            return 1
        fi
    elif [[ "${checkType}" == "packageManager" ]]; then
        if [ "${value}" == "${systemPackage}" ]; then
            return 0
        else
            return 1
        fi
    fi
}

version_gt(){
    test "$(echo "$@" | tr " " "\n" | sort -V | head -n 1)" != "$1"
}

check_kernel_version(){
    local kernel_version=$(uname -r | cut -d- -f1)
    if version_gt ${kernel_version} 3.7.0; then
        return 0
    else
        return 1
    fi
}

check_kernel_headers(){
    if check_sys packageManager yum; then
        if rpm -qa | grep -q headers-$(uname -r); then
            return 0
        else
            return 1
        fi
    elif check_sys packageManager apt; then
        if dpkg -s linux-headers-$(uname -r) > /dev/null 2>&1; then
            return 0
        else
            return 1
        fi
    fi
    return 1
}

# Get version
getversion(){
    if [[ -s /etc/redhat-release ]]; then
        grep -oE  "[0-9.]+" /etc/redhat-release
    else
        grep -oE  "[0-9.]+" /etc/issue
    fi
}

# CentOS version
centosversion(){
    if check_sys sysRelease centos; then
        local code=$1
        local version="$(getversion)"
        local main_ver=${version%%.*}
        if [ "$main_ver" == "$code" ]; then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

kill_progress(){
    for i in "ss-server" "ss-local" "ss-redir" "ss-manager"; 
    do
        ps -ef | grep -v grep | grep -i $i > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            kill -9 `ps -ef | grep -v grep |  grep $i | awk '{print $2}'`
        fi
    done
}

# Pre-installation settings
pre_install(){
    # Check OS system
    if check_sys sysRelease centos; then
        # Not support CentOS 5
        if centosversion 5; then
            echo -e "[${red}Error${plain}] Not support CentOS 5, please change to CentOS 6 or 7 and try again."
            exit 1
        fi
    else
        echo -e "[${red}Error${plain}] Your OS is not supported to run it, please change OS to CentOS and try again."
        exit 1
    fi

    # Check version
    check_version
    status=$?
    if [ ${status} -eq 0 ]; then
        echo -e "[${green}Info${plain}] Latest version ${green}${shadowsocks_libev_ver}${plain} has already been installed, nothing to do..."
        exit 0
    elif [ ${status} -eq 1 ]; then
        echo -e "Installed version: ${red}${installed_ver}${plain}"
        echo -e "Latest version: ${red}${latest_ver}${plain}"
        echo -e "[${green}Info${plain}] Upgrade shadowsocks libev to latest version..."
        echo -e "[${green}Info${plain}] Start kill all shadowsocks progress"
        kill_progress
    elif [ ${status} -eq 2 ]; then
        print_info
        get_latest_version
        echo -e "[${green}Info${plain}] Latest version: ${green}${shadowsocks_libev_ver}${plain}"
        echo
    fi
}

config_file(){
    # Set shadowsocks-libev config password
    dpwd=`< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c6`
    echo "Please enter password for shadowsocks-libev:"
    read -p "(Default password: ${dpwd}):" shadowsockspwd
    [ -z "${shadowsockspwd}" ] && shadowsockspwd=${dpwd}
    echo
    echo "---------------------------"
    echo "password = ${shadowsockspwd}"
    echo "---------------------------"
    echo

    # Set shadowsocks-libev config port
    while true
    do
    dport=$(shuf -i 9000-19999 -n 1)
    echo -e "Please enter a port for shadowsocks-libev [1-65535]"
    read -p "(Default port: ${dport}):" shadowsocksport
    [ -z "${shadowsocksport}" ] && shadowsocksport=${dport}
    expr ${shadowsocksport} + 1 &>/dev/null
    if [ $? -eq 0 ]; then
        if [ ${shadowsocksport} -ge 1 ] && [ ${shadowsocksport} -le 65535 ] && [ ${shadowsocksport:0:1} != 0 ]; then
            echo
            echo "---------------------------"
            echo "port = ${shadowsocksport}"
            echo "---------------------------"
            echo
            break
        fi
    fi
    echo -e "[${red}Error${plain}] Please enter a correct number [1-65535]"
    done

    # Set shadowsocks config stream ciphers
    while true
    do
    echo -e "Please select stream cipher for shadowsocks-libev:"
    for ((i=1;i<=${#ciphers[@]};i++ )); do
        hint="${ciphers[$i-1]}"
        echo -e "${green}${i}${plain}) ${hint}"
    done
    read -p "Which cipher you'd select(Default: ${ciphers[0]}):" pick
    [ -z "$pick" ] && pick=1
    expr ${pick} + 1 &>/dev/null
    if [ $? -ne 0 ]; then
        echo -e "[${red}Error${plain}] Please enter a number"
        continue
    fi
    if [[ "$pick" -lt 1 || "$pick" -gt ${#ciphers[@]} ]]; then
        echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#ciphers[@]}"
        continue
    fi
    shadowsockscipher=${ciphers[$pick-1]}
    echo
    echo "---------------------------"
    echo "cipher = ${shadowsockscipher}"
    echo "---------------------------"
    echo
    break
    done
}

# $1-config file name
config_server_file(){
    # base config
    config_file

    # dns
    local server_value="\"0.0.0.0\""
    if get_ipv6; then
        server_value="[\"[::0]\",\"0.0.0.0\"]"
    fi

    # fast_open
    if check_kernel_version && check_kernel_headers; then
        fast_open="true"
    else
        fast_open="false"
    fi

    # config-file
    if [ ! -d /etc/shadowsocks-libev ]; then
        mkdir -p /etc/shadowsocks-libev
    fi
    server_config_file="/etc/shadowsocks-libev/ss-server-config.json"
    [ ! -z "$1" ] && server_config_file="/etc/shadowsocks-libev/$1-config.json"
    cat > ${server_config_file}<<-EOF
{
    "server":${server_value},
    "server_port":${shadowsocksport},
    "password":"${shadowsockspwd}",
    "timeout":300,
    "user":"nobody",
    "method":"${shadowsockscipher}",
    "fast_open":${fast_open},
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp"
}
EOF
}

# $1-config file name
config_server_file_default(){
    shadowsocksport=16028
    shadowsockspwd="P@ssw0rd1234561"
    shadowsockscipher="aes-192-cfb"

    # dns
    local server_value="\"0.0.0.0\""
    if get_ipv6; then
        server_value="[\"[::0]\",\"0.0.0.0\"]"
    fi

    # fast_open
    if check_kernel_version && check_kernel_headers; then
        fast_open="true"
    else
        fast_open="false"
    fi

    # config-file
    if [ ! -d /etc/shadowsocks-libev ]; then
        mkdir -p /etc/shadowsocks-libev
    fi
    server_config_file="/etc/shadowsocks-libev/ss-server-config.json"
    [ ! -z "$1" ] && server_config_file="/etc/shadowsocks-libev/$1-config.json"
    cat > ${server_config_file}<<-EOF
{
    "server":${server_value},
    "server_port":${shadowsocksport},
    "password":"${shadowsockspwd}",
    "timeout":300,
    "user":"nobody",
    "method":"${shadowsockscipher}",
    "fast_open":${fast_open},
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp"
}
EOF
}

config_local_file(){
    # Set shadowsocks-libev config server ip
    dip="8.8.8.8"
    echo "Please enter server ip for shadowsocks-libev:"
    read -p "(Default server ip: ${dip}):" shadowsocksip
    [ -z "${shadowsocksip}" ] && shadowsocksip=${dip}
    echo
    echo "---------------------------"
    echo "server ip = ${shadowsocksip}"
    echo "---------------------------"
    echo

    # base config
    config_file
    
    # config-file
    if [ ! -d /etc/shadowsocks-libev ]; then
        mkdir -p /etc/shadowsocks-libev
    fi
    local_config_file="/etc/shadowsocks-libev/ss-local-config.json"
    [ ! -z "$1" ] && local_config_file="/etc/shadowsocks-libev/$1-config.json"
    cat > ${local_config_file}<<-EOF
{
    "server": "${shadowsocksip}",
    "server_port": ${shadowsocksport},
    "method": "${shadowsockscipher}",
    "password": "${shadowsockspwd}",
    "local_address": "0.0.0.0",
    "local_port": ${shadowsockslocalport},
    "fast_open": ${fast_open},
    "workers": 1
}
EOF
}

# $1-service file name $2-config file path $3-daemon file name
config_service_file_and_start(){
    service_config_file="/etc/init.d/shadowsocks-libev"
    [ ! -z "$1" ] && service_config_file="/etc/init.d/shadowsocks-libev-$1"

    # log
    echo "shadowsocks-libev-$1" >> /etc/shadowsocks-libev/service-name.log

    cat > ${service_config_file}<<-EOF
#!/usr/bin/env bash
# chkconfig: 2345 90 10
# description: A secure socks5 proxy, designed to protect your Internet traffic.

### BEGIN INIT INFO
# Provides:          Shadowsocks-libev-$3
# Required-Start:    \$network \$syslog
# Required-Stop:     \$network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Fast tunnel proxy that helps you bypass firewalls
# Description:       Start or stop the Shadowsocks-libev-$3
### END INIT INFO

if [ -f /usr/local/bin/$3 ]; then
    DAEMON=/usr/local/bin/$3
elif [ -f /usr/bin/$3 ]; then
    DAEMON=/usr/bin/$3
fi
NAME=Shadowsocks-libev-$3
CONF=$2
PID_DIR=/var/run
PID_FILE=\$PID_DIR/shadowsocks-libev-$1.pid
RET_VAL=0

[ -x \$DAEMON ] || exit 0

if [ ! -d \$PID_DIR ]; then
    mkdir -p \$PID_DIR
    if [ \$? -ne 0 ]; then
        echo "Creating PID directory \$PID_DIR failed"
        exit 1
    fi
fi

if [ ! -f \$CONF ]; then
    echo "\$NAME config file \$CONF not found"
     exit 1
fi

check_running() {
    if [ -r \$PID_FILE ]; then
        read PID < \$PID_FILE
        if [ -d "/proc/\$PID" ]; then
            return 0
        else
            rm -f \$PID_FILE
            return 1
        fi
    else
        return 2
    fi
}

do_status() {
    check_running
    case \$? in
        0)
        echo "\$NAME (pid \$PID) is running..."
        ;;
        1|2)
        echo "\$NAME is stopped"
        RET_VAL=1
        ;;
    esac
}

do_start() {
    if check_running; then
        echo "\$NAME (pid \$PID) is already running..."
        return 0
    fi
    \$DAEMON -v -c \$CONF -f \$PID_FILE
    if check_running; then
        echo "Starting \$NAME success"
    else
        echo "Starting \$NAME failed"
        RET_VAL=1
    fi
}

do_stop() {
    if check_running; then
        kill -9 \$PID
        rm -f \$PID_FILE
        echo "Stopping \$NAME success"
    else
        echo "\$NAME is stopped"
        RET_VAL=1
    fi
}

do_restart() {
    do_stop
    sleep 0.5
    do_start
}

case "\$1" in
    start|stop|restart|status)
    do_\$1
    ;;
    *)
    echo "Usage: \$0 { start | stop | restart | status }"
    RET_VAL=1
    ;;
esac

exit \$RET_VAL

EOF

    chmod +x ${service_config_file}
    chkconfig --add shadowsocks-libev-$1
    chkconfig shadowsocks-libev-$1 on
    # Start
    ${service_config_file} start
    if [ $? -eq 0 ]; then
        echo -e "[${green}Info${plain}] shadowsocks-libev-$1 start success!"
    else
        echo -e "[${yellow}Warning${plain}] shadowsocks-libev-$1 start failure!"
    fi
}

download() {
    local filename=${1}
    local cur_dir=`pwd`
    if [ -s ${filename} ]; then
        echo -e "[${green}Info${plain}] ${filename} [found]"
    else
        echo -e "[${green}Info${plain}] ${filename} not found, download now..."
        wget --no-check-certificate -cq -t3 -T60 -O ${1} ${2}
        if [ $? -eq 0 ]; then
            echo -e "[${green}Info${plain}] ${filename} download completed..."
        else
            echo -e "[${red}Error${plain}] Failed to download ${filename}, please download it to ${cur_dir} directory manually and try again."
            exit 1
        fi
    fi
}

# Download latest shadowsocks-libev
download_files(){
    cd ${cur_dir}
    download "${shadowsocks_libev_ver}.tar.gz" "${download_link}"
    download "${libsodium_file}.tar.gz" "${libsodium_url}"
    download "${mbedtls_file}-gpl.tgz" "${mbedtls_url}"
}

clear_download_files(){
    cd ${cur_dir}
    rm -rf "${shadowsocks_libev_ver}.tar.gz"
    rm -rf "${libsodium_file}.tar.gz"
    rm -rf "${mbedtls_file}-gpl.tgz"
}

go_start(){
    echo
    echo "Press any key to start...or press Ctrl+C to cancel"
    char=`get_char`
}

install_necessary_dependencies(){
    #Install necessary dependencies
    echo -e "[${green}Info${plain}] Checking the EPEL repository..."
    if [ ! -f /etc/yum.repos.d/epel.repo ]; then
        yum install -y -q epel-release
    fi
    [ ! -f /etc/yum.repos.d/epel.repo ] && echo -e "[${red}Error${plain}] Install EPEL repository failed, please check it." && exit 1
    [ ! "$(command -v yum-config-manager)" ] && yum install -y -q yum-utils
    if [ x"`yum-config-manager epel | grep -w enabled | awk '{print $3}'`" != x"True" ]; then
        yum-config-manager --enable epel
    fi
    echo -e "[${green}Info${plain}] Checking the EPEL repository complete..."
    yum install -y -q unzip openssl openssl-devel gettext gcc autoconf libtool automake make asciidoc xmlto libev-devel pcre pcre-devel git c-ares-devel
}

install_libsodium() {
    if [ ! -f /usr/lib/libsodium.a ]; then
        cd ${cur_dir}
        tar zxf ${libsodium_file}.tar.gz
        cd ${libsodium_file}
        ./configure --prefix=/usr && make && make install
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] ${libsodium_file} install failed."
            exit 1
        fi
    else
        echo -e "[${green}Info${plain}] ${libsodium_file} already installed."
    fi
}

install_mbedtls() {
    if [ ! -f /usr/lib/libmbedtls.a ]; then
        cd ${cur_dir}
        tar xf ${mbedtls_file}-gpl.tgz
        cd ${mbedtls_file}
        make SHARED=1 CFLAGS=-fPIC
        make DESTDIR=/usr install
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] ${mbedtls_file} install failed."
            exit 1
        fi
    else
        echo -e "[${green}Info${plain}] ${mbedtls_file} already installed."
    fi
}

# Install Shadowsocks-libev
install_shadowsocks(){
    install_necessary_dependencies
    install_libsodium
    install_mbedtls

    ldconfig
    cd ${cur_dir}
    tar zxf ${shadowsocks_libev_ver}.tar.gz
    cd ${shadowsocks_libev_ver}
    ./configure --disable-documentation
    make && make install
    if [ $? -eq 0 ]; then
        echo
        echo -e "[${green}Info${plain}] Shadowsocks-libev install success!"
    else
        echo
        echo -e "[${red}Error${plain}] Shadowsocks-libev install failed."
        exit 1
    fi

    clear_download_files
}

print_server_installed_info(){
    clear
    echo
    echo -e "Congratulations, Shadowsocks-libev server install completed!"
    echo -e "Your Server IP        : \033[41;37m $(get_ip) \033[0m"
    echo -e "Your Server Port      : \033[41;37m ${shadowsocksport} \033[0m"
    echo -e "Your Password         : \033[41;37m ${shadowsockspwd} \033[0m"
    echo -e "Your Encryption Method: \033[41;37m ${shadowsockscipher} \033[0m"
    echo
    echo "Enjoy it!"
    echo
}

# Firewall set for ss-server
firewall_set_ss_server(){
    echo -e "[${green}Info${plain}] firewall set start..."
    if centosversion 6; then
        /etc/init.d/iptables status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            iptables -L -n | grep -i ${shadowsocksport} > /dev/null 2>&1
            if [ $? -ne 0 ]; then
                iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport} -j ACCEPT
                iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport} -j ACCEPT
                /etc/init.d/iptables save
                /etc/init.d/iptables restart
            else
                echo -e "[${green}Info${plain}] port ${shadowsocksport} has been set up."
            fi
        else
            echo -e "[${yellow}Warning${plain}] iptables looks like shutdown or not installed, please manually set it if necessary."
        fi
    elif centosversion 7; then
        systemctl status firewalld > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            firewall-cmd --permanent --zone=public --add-port=${shadowsocksport}/tcp
            firewall-cmd --permanent --zone=public --add-port=${shadowsocksport}/udp
            firewall-cmd --reload
        else
            echo -e "[${yellow}Warning${plain}] firewalld looks like not running or not installed, please enable port ${shadowsocksport} manually if necessary."
        fi
    fi
    echo -e "[${green}Info${plain}] firewall set completed..."
}

# Install Shadowsocks-libev
install_shadowsocks_libev(){
    go_start
    disable_selinux
    pre_install
    download_files
    install_shadowsocks
}

# only config server
config_server(){
    config_server_file "ss-server"
    config_service_file_and_start "ss-server" "${config_server_file}" "ss-server" 
    print_server_installed_info 
}

# Install Shadowsocks-libev and config server
install_shadowsocks_libev_and_config_server(){
    config_server_file "ss-server"
    disable_selinux 
    pre_install
    download_files
    install_shadowsocks
    config_service_file_and_start "ss-server" "${config_server_file}" "ss-server" 
    print_server_installed_info 
}

# Install Shadowsocks-libev and config server auto default
install_shadowsocks_libev_and_config_server_default(){
    config_server_file_default
    disable_selinux 
    pre_install
    download_files
    install_shadowsocks
    config_service_file_and_start "ss-server" "${config_server_file}" "ss-server" 
    print_server_installed_info 
}

# Install Shadowsocks-libev and config local
# $1-config name $2-service name $3-daemon name
install_shadowsocks_libev_and_config_local(){
    config_server_file $1
    disable_selinux 
    pre_install
    download_files
    install_shadowsocks
    config_service_file_and_start $2 "${config_local_file}" $3  
    cat ${config_local_file}
}

# only config local
# $1-config name $2-service name $3-daemon name
config_local(){
    config_server_file $1
    config_service_file_and_start $2 "${config_local_file}" $3  
    cat ${config_local_file}
}

# Uninstall Shadowsocks-libev
uninstall_shadowsocks_libev(){
    clear
    print_info
    printf "Are you sure uninstall shadowsocks-libev? (y/n)"
    printf "\n"
    read -p "(Default: n):" answer
    [ -z ${answer} ] && answer="n"

    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        kill_progress

        if [ -f /etc/shadowsocks-libev/service-name.log ]; then
            for i in `cat /etc/shadowsocks-libev/service-name.log`;
            do
            chkconfig --del $i
            done
        fi
        
        rm -fr /etc/shadowsocks-libev
        rm -f /usr/local/bin/ss-local
        rm -f /usr/local/bin/ss-tunnel
        rm -f /usr/local/bin/ss-server
        rm -f /usr/local/bin/ss-manager
        rm -f /usr/local/bin/ss-redir
        rm -f /usr/local/bin/ss-nat
        rm -f /usr/local/lib/libshadowsocks-libev.a
        rm -f /usr/local/lib/libshadowsocks-libev.la
        rm -f /usr/local/include/shadowsocks.h
        rm -f /usr/local/lib/pkgconfig/shadowsocks-libev.pc
        rm -f /usr/local/share/man/man1/ss-local.1
        rm -f /usr/local/share/man/man1/ss-tunnel.1
        rm -f /usr/local/share/man/man1/ss-server.1
        rm -f /usr/local/share/man/man1/ss-manager.1
        rm -f /usr/local/share/man/man1/ss-redir.1
        rm -f /usr/local/share/man/man1/ss-nat.1
        rm -f /usr/local/share/man/man8/shadowsocks-libev.8
        rm -fr /usr/local/share/doc/shadowsocks-libev
        rm -f /etc/init.d/shadowsocks-libev-*
        echo "shadowsocks-libev uninstall success!"
    else
        echo
        echo "uninstall cancelled, nothing to do..."
        echo
    fi
}

# Initialization step
print_use_help(){
    clear
    echo
    echo -e "Usage: ss-install [install|uninstall|install_server|install_server_default|install_local|...] [arg1]..."
    echo -e "install                    : \033[41;37m only install shadowsocks-libev \033[0m"
    echo -e "uninstall                  : \033[41;37m uninstall shadowsocks-libev \033[0m"
    echo -e "install_server             : \033[41;37m install shadowsocks-libev and config server \033[0m"
    echo -e "install_server_default     : \033[41;37m auto install shadowsocks-libev and set default config \033[0m"
    echo -e "install_local              : \033[41;37m install shadowsocks-libev and config local \033[0m"
    echo -e "   -arg:[--config-name]    : \033[41;37m       config name \033[0m"
    echo -e "   -arg:[--service-name]   : \033[41;37m       service name \033[0m"
    echo -e "   -arg:[--daemon-name]    : \033[41;37m       daemon name \033[0m"
    echo -e "config_local               : \033[41;37m only config local \033[0m"
    echo -e "   -arg:[--config-name]    : \033[41;37m       config name \033[0m"
    echo -e "   -arg:[--service-name]   : \033[41;37m       service name \033[0m"
    echo -e "   -arg:[--daemon-name]    : \033[41;37m       daemon name \033[0m"
    echo -e "config_server              : \033[41;37m only config server \033[0m"
    echo -e "show_config_list           : \033[41;37m show all config file \033[0m"
    echo -e "show_service_list          : \033[41;37m show all service \033[0m"
    echo -e "clear_download_files       : \033[41;37m clear download files \033[0m"
    echo
}

main(){
    check_root
    echo hello 

    action=$1
    while [ "$1" != "${1##[-+]}" ]; do
        case $1 in
        '')
            print_use_help
            return 1
            ;;
        --config_name)
            config_name=$2
            shift 2
            ;;
        --config_name=?*)
            config_name=${1#--config_name=}
            shift
            ;;
        --service_name)
            service_name=$2
            shift 2
            ;;
        --service_name=?*)
            service_name=${1#--service_name=}
            shift
            ;;
        --daemon_name)
            daemon_name=$2
            shift 2
            ;;
        --daemon_name=?*)
            daemon_name=${1#--daemon_name=}
            shift
            ;;
        *)
            print_use_help
            return 1
            ;;
        esac
    done

    echo ${action} ${config_name}

    case ${action} in
    'install')
        install_shadowsocks_libev
        ;;
    'uninstall')
        uninstall_shadowsocks_libev
        ;;
    'install_server')
        install_shadowsocks_libev_and_config_server
        ;;
    'install_server_default')
        install_shadowsocks_libev_and_config_server_default
        ;;
    'install_local')
        install_shadowsocks_libev_and_config_local ${config_name} ${service_name} ${daemon_name}
        ;;
    'config_local')
        config_local ${config_name} ${service_name} ${daemon_name}
        ;;
    'config_server')
        config_server
        ;;
    'show_config_list')
        ls -al /etc/shadowsocks-libev/*
        ;;
    'show_service_list')
        cat /etc/shadowsocks-libev/service-name.log
        ;;
    'clear_download_files')
        clear_download_files
        ;;
    esac
}
main $@