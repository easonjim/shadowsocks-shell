# shadowsocks-shell
shadowsocks install shell for centos  
fork by https://github.com/teddysun/shadowsocks_install  
Increase the automatic deployment configuration to achieve server deployment in batches.

## use help
```shell
#############################################################
# Install shadowsocks-libev server for CentOS 6 or 7        #
#############################################################


Usage: ss-install [help|install|uninstall|install_server|install_server_default|install_local|...] [arg1]...
help                       :  print this help info 
install                    :  only install shadowsocks-libev 
update                     :  only update shadowsocks-libev 
uninstall                  :  uninstall shadowsocks-libev 
install_server             :  install shadowsocks-libev and config server 
install_server_default     :  auto install shadowsocks-libev and set default config 
install_server_auto        :  auto install shadowsocks-libev and auto config 
   -arg:[--config_name]    :        config name,default is ss-server 
   -arg:[--service_name]   :        service name,default is ss-server 
   -arg:[--port]           :        port,default is 16028 
   -arg:[--password]       :        password,default is P@ssw0rd1234561 
   -arg:[--cipher]         :        cipher,default is aes-192-cfb 
install_local              :  install shadowsocks-libev and config local 
   -arg:[--config_name]    :        config name,default is ss-local 
   -arg:[--service_name]   :        service name,default is ss-local 
   -arg:[--daemon_name]    :        daemon name,default is ss-local 
install_local_auto         :  install shadowsocks-libev and auto config local 
   -arg:[--config_name]    :        config name,default is ss-local 
   -arg:[--service_name]   :        service name,default is ss-local 
   -arg:[--daemon_name]    :        daemon name,default is ss-local 
   -arg:[--server_ip]      :        server ip,default is 8.8.8.8 
   -arg:[--port]           :        port,default is 16028 
   -arg:[--password]       :        password,default is P@ssw0rd1234561 
   -arg:[--cipher]         :        cipher,default is aes-192-cfb 
   -arg:[--local_port]     :        local port,default is 1080 
config_local               :  only config local 
   -arg:[--config_name]    :        config name,default is ss-local 
   -arg:[--service_name]   :        service name,default is ss-local 
   -arg:[--daemon_name]    :        daemon name,default is ss-local 
config_server              :  only config server 
show_config_list           :  show all config file 
show_service_list          :  show all service 
clear_download_files       :  clear download files 
```

## Example
#### default install server
```shell
    bash ss-install.sh install_server_default
```
the config content was be:
```shell
    cat /etc/shadowsocks-libev/ss-server-config.json 
    {
        "server":"0.0.0.0",
        "server_port":16028,
        "password":"P@ssw0rd1234561",
        "timeout":300,
        "user":"nobody",
        "method":"aes-192-cfb",
        "fast_open":false,
        "nameserver":"8.8.8.8",
        "mode":"tcp_and_udp"
    }
```
#### auto install server
can be set custom parameter
```shell
    bash ss-install.sh install_server_auto --config_name "ss-server" --port "16028" --password "ssw0rd1234561" --cipher "aes-256-cfb"
```
#### auto install local
can be use for ss-local|ss-redir|ss-tunnel|ss-manager
```shell
    bash ss-install.sh install_local_auto --config_name "ss-local" --service_name "ss-local" --daemon_name "ss-local" --server_ip "127.0.0.2" --port "16088" --password "ssw0rd1234561" --cipher "aes-192-cfb" --local_port 1089
```

## quick start
quick start deploy default ss-server
#### curl
```shell
     curl -fsSL https://raw.githubusercontent.com/easonjim/shadowsocks-shell/master/ss-install.sh | bash -s "install_server_default" 2>&1 | tee shadowsocks-libev.log
```
#### git
```shell
    git clone https://github.com/easonjim/shadowsocks-shell
    bash shadowsocks-shell/ss-install.sh install_server_default 2>&1 | tee shadowsocks-libev.log
```