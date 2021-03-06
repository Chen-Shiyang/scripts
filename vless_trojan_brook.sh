#!/bin/bash

export LC_ALL=C
#export LANG=C
export LANG=en_US.UTF-8
export LANGUAGE=en_US.UTF-8

# BBR
echo net.core.default_qdisc=fq >> /etc/sysctl.conf
echo net.ipv4.tcp_congestion_control=bbr >> /etc/sysctl.conf
sysctl -p && sysctl net.ipv4.tcp_available_congestion_control
lsmod | grep bbr

wget https://github.com/txthinking/brook/releases/download/v20210701/brook_linux_amd64
chmod +x /root/brook_linux_amd64

cat >/etc/systemd/system/brook.service<<-EOF
[Unit]
Description=brook Service
After=network.target nss-lookup.target

[Service]
User=root
#User=nobody
#CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
#AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/root/brook_linux_amd64 wsserver --listen :666 --password hello
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable brook.service
systemctl restart brook.service

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
  sudoCmd="sudo"
else
  sudoCmd=""
fi

uninstall() {
  ${sudoCmd} $(which rm) -rf $1
  printf "File or Folder Deleted: %s\n" $1
}


# fonts color
red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}
green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}
yellow(){
    echo -e "\033[33m\033[01m$1\033[0m"
}
blue(){
    echo -e "\033[34m\033[01m$1\033[0m"
}
bold(){
    echo -e "\033[1m\033[01m$1\033[0m"
}


osCPU="intel"
osArchitecture="arm"
osInfo=""
osRelease=""
osReleaseVersion=""
osReleaseVersionNo=""
osReleaseVersionCodeName="CodeName"
osSystemPackage=""
osSystemMdPath=""
osSystemShell="bash"


function checkArchitecture(){
	# https://stackoverflow.com/questions/48678152/how-to-detect-386-amd64-arm-or-arm64-os-architecture-via-shell-bash

	case $(uname -m) in
		i386)   osArchitecture="386" ;;
		i686)   osArchitecture="386" ;;
		x86_64) osArchitecture="amd64" ;;
		arm)    dpkg --print-architecture | grep -q "arm64" && osArchitecture="arm64" || osArchitecture="arm" ;;
		* )     osArchitecture="arm" ;;
	esac
}

function checkCPU(){
	osCPUText=$(cat /proc/cpuinfo | grep vendor_id | uniq)
	if [[ $osCPUText =~ "GenuineIntel" ]]; then
		osCPU="intel"
    else
        osCPU="amd"
    fi

	# green " Status ????????????--??????CPU???: $osCPU"
}

# ???????????????????????????
function getLinuxOSRelease(){
    if [[ -f /etc/redhat-release ]]; then
        osRelease="centos"
        osSystemPackage="yum"
        osSystemMdPath="/usr/lib/systemd/system/"
        osReleaseVersionCodeName=""
    elif cat /etc/issue | grep -Eqi "debian|raspbian"; then
        osRelease="debian"
        osSystemPackage="apt-get"
        osSystemMdPath="/lib/systemd/system/"
        osReleaseVersionCodeName="buster"
    elif cat /etc/issue | grep -Eqi "ubuntu"; then
        osRelease="ubuntu"
        osSystemPackage="apt-get"
        osSystemMdPath="/lib/systemd/system/"
        osReleaseVersionCodeName="bionic"
    elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
        osRelease="centos"
        osSystemPackage="yum"
        osSystemMdPath="/usr/lib/systemd/system/"
        osReleaseVersionCodeName=""
    elif cat /proc/version | grep -Eqi "debian|raspbian"; then
        osRelease="debian"
        osSystemPackage="apt-get"
        osSystemMdPath="/lib/systemd/system/"
        osReleaseVersionCodeName="buster"
    elif cat /proc/version | grep -Eqi "ubuntu"; then
        osRelease="ubuntu"
        osSystemPackage="apt-get"
        osSystemMdPath="/lib/systemd/system/"
        osReleaseVersionCodeName="bionic"
    elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
        osRelease="centos"
        osSystemPackage="yum"
        osSystemMdPath="/usr/lib/systemd/system/"
        osReleaseVersionCodeName=""
    fi

    getLinuxOSVersion
    checkArchitecture
	checkCPU

    [[ -z $(echo $SHELL|grep zsh) ]] && osSystemShell="bash" || osSystemShell="zsh"

    green " ????????????: ${osInfo}, ${osRelease}, ${osReleaseVersion}, ${osReleaseVersionNo}, ${osReleaseVersionCodeName}, ${osCPU} CPU ${osArchitecture}, ${osSystemShell}, ${osSystemPackage}, ${osSystemMdPath}"
}

# ?????????????????????
getLinuxOSVersion(){
    if [[ -s /etc/redhat-release ]]; then
        osReleaseVersion=$(grep -oE '[0-9.]+' /etc/redhat-release)
    else
        osReleaseVersion=$(grep -oE '[0-9.]+' /etc/issue)
    fi

    # https://unix.stackexchange.com/questions/6345/how-can-i-get-distribution-name-and-version-number-in-a-simple-shell-script

    if [ -f /etc/os-release ]; then
        # freedesktop.org and systemd
        source /etc/os-release
        osInfo=$NAME
        osReleaseVersionNo=$VERSION_ID

        if [ -n $VERSION_CODENAME ]; then
            osReleaseVersionCodeName=$VERSION_CODENAME
        fi
    elif type lsb_release >/dev/null 2>&1; then
        # linuxbase.org
        osInfo=$(lsb_release -si)
        osReleaseVersionNo=$(lsb_release -sr)
    elif [ -f /etc/lsb-release ]; then
        # For some versions of Debian/Ubuntu without lsb_release command
        . /etc/lsb-release
        osInfo=$DISTRIB_ID
        
        osReleaseVersionNo=$DISTRIB_RELEASE
    elif [ -f /etc/debian_version ]; then
        # Older Debian/Ubuntu/etc.
        osInfo=Debian
        osReleaseVersion=$(cat /etc/debian_version)
        osReleaseVersionNo=$(sed 's/\..*//' /etc/debian_version)
    elif [ -f /etc/redhat-release ]; then
        osReleaseVersion=$(grep -oE '[0-9.]+' /etc/redhat-release)
    else
        # Fall back to uname, e.g. "Linux <version>", also works for BSD, etc.
        osInfo=$(uname -s)
        osReleaseVersionNo=$(uname -r)
    fi
}

osPort80=""
osPort443=""
osSELINUXCheck=""
osSELINUXCheckIsRebootInput=""

function testLinuxPortUsage(){
    $osSystemPackage -y install net-tools socat

    osPort80=`netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w 80`
    osPort443=`netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w 443`

    if [ -n "$osPort80" ]; then
        process80=`netstat -tlpn | awk -F '[: ]+' '$5=="80"{print $9}'`
        red "==========================================================="
        red "?????????80????????????????????????????????????${process80}?????????????????????"
        red "==========================================================="
        exit 1
    fi

    if [ -n "$osPort443" ]; then
        process443=`netstat -tlpn | awk -F '[: ]+' '$5=="443"{print $9}'`
        red "============================================================="
        red "?????????443????????????????????????????????????${process443}?????????????????????"
        red "============================================================="
        exit 1
    fi

    osSELINUXCheck=$(grep SELINUX= /etc/selinux/config | grep -v "#")
    if [ "$osSELINUXCheck" == "SELINUX=enforcing" ]; then
        red "======================================================================="
        red "?????????SELinux????????????????????????????????????????????????????????????????????????VPS????????????????????????"
        red "======================================================================="
        read -p "??????????????????? ????????? [Y/n] :" osSELINUXCheckIsRebootInput
        [ -z "${osSELINUXCheckIsRebootInput}" ] && osSELINUXCheckIsRebootInput="y"

        if [[ $osSELINUXCheckIsRebootInput == [Yy] ]]; then
            sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
            setenforce 0
            echo -e "VPS ?????????..."
            reboot
        fi
        exit
    fi

    if [ "$osSELINUXCheck" == "SELINUX=permissive" ]; then
        red "======================================================================="
        red "?????????SELinux??????????????????????????????????????????????????????????????????VPS????????????????????????"
        red "======================================================================="
        read -p "??????????????????? ????????? [Y/n] :" osSELINUXCheckIsRebootInput
        [ -z "${osSELINUXCheckIsRebootInput}" ] && osSELINUXCheckIsRebootInput="y"

        if [[ $osSELINUXCheckIsRebootInput == [Yy] ]]; then
            sed -i 's/SELINUX=permissive/SELINUX=disabled/g' /etc/selinux/config
            setenforce 0
            echo -e "VPS ?????????..."
            reboot
        fi
        exit
    fi

    if [ "$osRelease" == "centos" ]; then
        if  [[ ${osReleaseVersionNo} == "6" || ${osReleaseVersionNo} == "5" ]]; then
            green " =================================================="
            red " ?????????????????? Centos 6 ??? Centos 6 ???????????????"
            green " =================================================="
            exit
        fi

        red " ??????????????? firewalld"
        ${sudoCmd} systemctl stop firewalld
        ${sudoCmd} systemctl disable firewalld

    elif [ "$osRelease" == "ubuntu" ]; then
        if  [[ ${osReleaseVersionNo} == "14" || ${osReleaseVersionNo} == "12" ]]; then
            green " =================================================="
            red " ?????????????????? Ubuntu 14 ??? Ubuntu 14 ???????????????"
            green " =================================================="
            exit
        fi

        red " ??????????????? ufw"
        ${sudoCmd} systemctl stop ufw
        ${sudoCmd} systemctl disable ufw
        
    elif [ "$osRelease" == "debian" ]; then
        $osSystemPackage update -y
    fi

}


# ?????? SSH ?????? ???????????? ???????????????
function editLinuxLoginWithPublicKey(){
    if [ ! -d "${HOME}/ssh" ]; then
        mkdir -p ${HOME}/.ssh
    fi

    vi ${HOME}/.ssh/authorized_keys
}



# ??????SSH root ??????

function setLinuxRootLogin(){

    read -p "??????????????????root??????(ssh???????????? ??? ?????????????????? )? ?????????[Y/n]:" osIsRootLoginInput
    osIsRootLoginInput=${osIsRootLoginInput:-Y}

    if [[ $osIsRootLoginInput == [Yy] ]]; then

        if [ "$osRelease" == "centos" ] || [ "$osRelease" == "debian" ] ; then
            ${sudoCmd} sed -i 's/#\?PermitRootLogin \(yes\|no\|Yes\|No\|prohibit-password\)/PermitRootLogin yes/g' /etc/ssh/sshd_config
        fi
        if [ "$osRelease" == "ubuntu" ]; then
            ${sudoCmd} sed -i 's/#\?PermitRootLogin prohibit-password/PermitRootLogin yes/g' /etc/ssh/sshd_config
        fi

        green "????????????root????????????!"
    fi


    read -p "??????????????????root??????????????????(???????????????????????????root???????????????)? ?????????[Y/n]:" osIsRootLoginWithPasswordInput
    osIsRootLoginWithPasswordInput=${osIsRootLoginWithPasswordInput:-Y}

    if [[ $osIsRootLoginWithPasswordInput == [Yy] ]]; then
        sed -i 's/#\?PasswordAuthentication \(yes\|no\)/PasswordAuthentication yes/g' /etc/ssh/sshd_config
        green "????????????root????????????????????????!"
    fi


    ${sudoCmd} sed -i 's/#\?TCPKeepAlive yes/TCPKeepAlive yes/g' /etc/ssh/sshd_config
    ${sudoCmd} sed -i 's/#\?ClientAliveCountMax 3/ClientAliveCountMax 30/g' /etc/ssh/sshd_config
    ${sudoCmd} sed -i 's/#\?ClientAliveInterval [0-9]*/ClientAliveInterval 40/g' /etc/ssh/sshd_config

    if [ "$osRelease" == "centos" ] ; then

        ${sudoCmd} service sshd restart
        ${sudoCmd} systemctl restart sshd

        green "????????????, ??????shell??????????????????vps?????????!"
    fi

    if [ "$osRelease" == "ubuntu" ] || [ "$osRelease" == "debian" ] ; then
        
        ${sudoCmd} service ssh restart
        ${sudoCmd} systemctl restart ssh

        green "????????????, ??????shell??????????????????vps?????????!"
    fi

    # /etc/init.d/ssh restart

}


# ??????SSH ?????????
function changeLinuxSSHPort(){
    green " ?????????SSH??????????????????, ??????????????????????????????. ?????? 20|21|23|25|53|69|80|110|443|123!"
    read -p "??????????????????????????????(???????????????????????????1024~65535?????????22):" osSSHLoginPortInput
    osSSHLoginPortInput=${osSSHLoginPortInput:-0}

    if [ $osSSHLoginPortInput -eq 22 -o $osSSHLoginPortInput -gt 1024 -a $osSSHLoginPortInput -lt 65535 ]; then
        sed -i "s/#\?Port [0-9]*/Port $osSSHLoginPortInput/g" /etc/ssh/sshd_config

        if [ "$osRelease" == "centos" ] ; then

            if  [[ ${osReleaseVersionNo} == "7" ]]; then
                yum -y install policycoreutils-python
            elif  [[ ${osReleaseVersionNo} == "8" ]]; then
                yum -y install policycoreutils-python-utils
            fi

            # semanage port -l
            semanage port -a -t ssh_port_t -p tcp $osSSHLoginPortInput
            firewall-cmd --permanent --zone=public --add-port=$osSSHLoginPortInput/tcp 
            firewall-cmd --reload
    
            ${sudoCmd} systemctl restart sshd.service

        fi

        if [ "$osRelease" == "ubuntu" ] || [ "$osRelease" == "debian" ] ; then
            semanage port -a -t ssh_port_t -p tcp $osSSHLoginPortInput
            sudo ufw allow $osSSHLoginPortInput/tcp

            ${sudoCmd} service ssh restart
            ${sudoCmd} systemctl restart ssh
        fi

        green "????????????, ??????????????????????????? ${osSSHLoginPortInput}!"
        green "?????????????????????: ssh -p ${osSSHLoginPortInput} root@111.111.111.your ip !"
    else
        echo "????????????????????????! ??????: 22,1025~65534"
    fi
}

function setLinuxDateZone(){

    tempCurrentDateZone=$(date +'%z')

    echo
    if [[ ${tempCurrentDateZone} == "+0800" ]]; then
        yellow "?????????????????????????????????  $tempCurrentDateZone | $(date -R) "
    else 
        green " =================================================="
        yellow " ???????????????: $tempCurrentDateZone | $(date -R) "
        yellow " ????????????????????????????????? +0800???, ??????cron??????????????????????????????????????????."
        green " =================================================="
        # read ????????? https://stackoverflow.com/questions/2642585/read-a-variable-in-bash-with-a-default-value

        read -p "??????????????????????????? +0800 ??????? ?????????[Y/n]:" osTimezoneInput
        osTimezoneInput=${osTimezoneInput:-Y}

        if [[ $osTimezoneInput == [Yy] ]]; then
            if [[ -f /etc/localtime ]] && [[ -f /usr/share/zoneinfo/Asia/Shanghai ]];  then
                mv /etc/localtime /etc/localtime.bak
                cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

                yellow "????????????! ???????????????????????? $(date -R)"
                green " =================================================="
            fi
        fi

    fi
    echo
}




# ???????????????
function upgradeScript(){
    wget -Nq --no-check-certificate -O ./trojan_v2ray_install.sh "https://raw.githubusercontent.com/jinwyp/one_click_script/master/trojan_v2ray_install.sh"
    green " ?????????????????????! "
    chmod +x ./trojan_v2ray_install.sh
    sleep 2s
    exec "./trojan_v2ray_install.sh"
}



# ????????????

function installSoftDownload(){
	if [[ "${osRelease}" == "debian" || "${osRelease}" == "ubuntu" ]]; then
		if ! dpkg -l | grep -qw wget; then
			${osSystemPackage} -y install wget git
			
			# https://stackoverflow.com/questions/11116704/check-if-vt-x-is-activated-without-having-to-reboot-in-linux
			${osSystemPackage} -y install cpu-checker
		fi

		if ! dpkg -l | grep -qw curl; then
			${osSystemPackage} -y install curl git
			
			${osSystemPackage} -y install cpu-checker
		fi

	elif [[ "${osRelease}" == "centos" ]]; then
		if ! rpm -qa | grep -qw wget; then
			${osSystemPackage} -y install wget curl git
		fi
	fi 
}

function installPackage(){
    if [ "$osRelease" == "centos" ]; then
       
        # rpm -Uvh http://nginx.org/packages/centos/7/noarch/RPMS/nginx-release-centos-7-0.el7.ngx.noarch.rpm

        cat > "/etc/yum.repos.d/nginx.repo" <<-EOF
[nginx]
name=nginx repo
baseurl=https://nginx.org/packages/centos/$osReleaseVersionNo/\$basearch/
gpgcheck=0
enabled=1

EOF
        if ! rpm -qa | grep -qw iperf3; then
			${sudoCmd} ${osSystemPackage} install -y epel-release

            ${osSystemPackage} install -y curl wget git unzip zip tar
            ${osSystemPackage} install -y xz jq redhat-lsb-core 
            ${osSystemPackage} install -y iputils
            ${osSystemPackage} install -y iperf3
		fi

        ${osSystemPackage} update -y


        # https://www.cyberciti.biz/faq/how-to-install-and-use-nginx-on-centos-8/
        if  [[ ${osReleaseVersionNo} == "8" ]]; then
            ${sudoCmd} yum module -y reset nginx
            ${sudoCmd} yum module -y enable nginx:1.18
            ${sudoCmd} yum module list nginx
        fi

    elif [ "$osRelease" == "ubuntu" ]; then
        
        # https://joshtronic.com/2018/12/17/how-to-install-the-latest-nginx-on-debian-and-ubuntu/
        # https://www.nginx.com/resources/wiki/start/topics/tutorials/install/
        
        $osSystemPackage install -y gnupg2
        wget -O - https://nginx.org/keys/nginx_signing.key | ${sudoCmd} apt-key add -

        cat > "/etc/apt/sources.list.d/nginx.list" <<-EOF
deb https://nginx.org/packages/ubuntu/ $osReleaseVersionCodeName nginx
deb-src https://nginx.org/packages/ubuntu/ $osReleaseVersionCodeName nginx
EOF

        ${osSystemPackage} update -y

        if ! dpkg -l | grep -qw iperf3; then
            ${sudoCmd} ${osSystemPackage} install -y software-properties-common
            ${osSystemPackage} install -y curl wget git unzip zip tar
            ${osSystemPackage} install -y xz-utils jq lsb-core lsb-release
            ${osSystemPackage} install -y iputils-ping
            ${osSystemPackage} install -y iperf3
		fi    

    elif [ "$osRelease" == "debian" ]; then
        # ${sudoCmd} add-apt-repository ppa:nginx/stable -y

        ${osSystemPackage} install -y gnupg2
        wget -O - https://nginx.org/keys/nginx_signing.key | ${sudoCmd} apt-key add -
        # curl -L https://nginx.org/keys/nginx_signing.key | ${sudoCmd} apt-key add -

        cat > "/etc/apt/sources.list.d/nginx.list" <<-EOF 
deb http://nginx.org/packages/debian/ $osReleaseVersionCodeName nginx
deb-src http://nginx.org/packages/debian/ $osReleaseVersionCodeName nginx
EOF
        
        ${osSystemPackage} update -y

        if ! dpkg -l | grep -qw iperf3; then
            ${osSystemPackage} install -y curl wget git unzip zip tar
            ${osSystemPackage} install -y xz-utils jq lsb-core lsb-release
            ${osSystemPackage} install -y iputils-ping
            ${osSystemPackage} install -y iperf3
        fi        
    fi
}


function installSoftEditor(){
    # ?????? micro ?????????
    if [[ ! -f "${HOME}/bin/micro" ]] ;  then
        mkdir -p ${HOME}/bin
        cd ${HOME}/bin
        curl https://getmic.ro | bash

        cp ${HOME}/bin/micro /usr/local/bin

        green " =================================================="
        green " micro ????????? ????????????!"
        green " =================================================="
    fi

    if [ "$osRelease" == "centos" ]; then   
        $osSystemPackage install -y xz  vim-minimal vim-enhanced vim-common
    else
        $osSystemPackage install -y vim-gui-common vim-runtime vim 
    fi

    # ??????vim ????????????
    if [[ ! -d "${HOME}/.vimrc" ]] ;  then
        cat > "${HOME}/.vimrc" <<-EOF
set fileencodings=utf-8,gb2312,gb18030,gbk,ucs-bom,cp936,latin1
set enc=utf8
set fencs=utf8,gbk,gb2312,gb18030

syntax on
colorscheme elflord

if has('mouse')
  se mouse+=a
  set number
endif

EOF
    fi
}

function installSoftOhMyZsh(){

    echo
    green " =================================================="
    yellow " ???????????? ZSH"
    green " =================================================="
    echo

    if [ "$osRelease" == "centos" ]; then

        ${sudoCmd} $osSystemPackage install zsh -y
        $osSystemPackage install util-linux-user -y

    elif [ "$osRelease" == "ubuntu" ]; then

        ${sudoCmd} $osSystemPackage install zsh -y

    elif [ "$osRelease" == "debian" ]; then

        ${sudoCmd} $osSystemPackage install zsh -y
    fi

    green " =================================================="
    green " ZSH ????????????"
    green " =================================================="

    # ?????? oh-my-zsh
    if [[ ! -d "${HOME}/.oh-my-zsh" ]] ;  then

        green " =================================================="
        yellow " ???????????? oh-my-zsh"
        green " =================================================="
        curl -Lo ${HOME}/ohmyzsh_install.sh https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh
        chmod +x ${HOME}/ohmyzsh_install.sh
        sh ${HOME}/ohmyzsh_install.sh --unattended
    fi

    if [[ ! -d "${HOME}/.oh-my-zsh/custom/plugins/zsh-autosuggestions" ]] ;  then
        git clone "https://github.com/zsh-users/zsh-autosuggestions" "${HOME}/.oh-my-zsh/custom/plugins/zsh-autosuggestions"

        # ?????? zshrc ??????
        zshConfig=${HOME}/.zshrc
        zshTheme="maran"
        sed -i 's/ZSH_THEME=.*/ZSH_THEME="'"${zshTheme}"'"/' $zshConfig
        sed -i 's/plugins=(git)/plugins=(git cp history z rsync colorize nvm zsh-autosuggestions)/' $zshConfig

        zshAutosuggestionsConfig=${HOME}/.oh-my-zsh/custom/plugins/zsh-autosuggestions/zsh-autosuggestions.zsh
        sed -i "s/ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=8'/ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=1'/" $zshAutosuggestionsConfig


        # Actually change the default shell to zsh
        zsh=$(which zsh)

        if ! chsh -s "$zsh"; then
            red "chsh command unsuccessful. Change your default shell manually."
        else
            export SHELL="$zsh"
            green "===== Shell successfully changed to '$zsh'."
        fi


        echo 'alias lla="ls -ahl"' >> ${HOME}/.zshrc
        echo 'alias mi="micro"' >> ${HOME}/.zshrc

        green " =================================================="
        yellow " oh-my-zsh ????????????, ??????exit??????????????????????????????????????????!"
        green " =================================================="

    fi

}



# ????????????

function vps_netflix(){
    # bash <(curl -sSL https://raw.githubusercontent.com/Netflixxp/NF/main/nf.sh)
    # bash <(curl -sSL "https://github.com/CoiaPrant/Netflix_Unlock_Information/raw/main/netflix.sh")
	# wget -N --no-check-certificate https://github.com/CoiaPrant/Netflix_Unlock_Information/raw/main/netflix.sh && chmod +x netflix.sh && ./netflix.sh

	wget -N --no-check-certificate -O ./netflix.sh https://github.com/CoiaPrant/MediaUnlock_Test/raw/main/check.sh && chmod +x ./netflix.sh && ./netflix.sh

    # wget -N -O nf https://github.com/sjlleo/netflix-verify/releases/download/2.01/nf_2.01_linux_amd64 && chmod +x nf && clear && ./nf
}


function vps_superspeed(){
	bash <(curl -Lso- https://git.io/superspeed)
	#wget -N --no-check-certificate https://raw.githubusercontent.com/ernisn/superspeed/master/superspeed.sh && chmod +x superspeed.sh && ./superspeed.sh
}

function vps_bench(){
	wget -N --no-check-certificate https://raw.githubusercontent.com/teddysun/across/master/bench.sh && chmod +x bench.sh && bash bench.sh
}

function vps_zbench(){
	wget -N --no-check-certificate https://raw.githubusercontent.com/FunctionClub/ZBench/master/ZBench-CN.sh && chmod +x ZBench-CN.sh && bash ZBench-CN.sh
}

function vps_testrace(){
	wget -N --no-check-certificate https://raw.githubusercontent.com/nanqinlang-script/testrace/master/testrace.sh && chmod +x testrace.sh && ./testrace.sh
}

function vps_LemonBench(){
    wget -O LemonBench.sh -N --no-check-certificate https://ilemonra.in/LemonBenchIntl && chmod +x LemonBench.sh && ./LemonBench.sh fast
}




function installBBR(){
    wget -O tcp_old.sh -N --no-check-certificate "https://raw.githubusercontent.com/chiakge/Linux-NetSpeed/master/tcp.sh" && chmod +x tcp_old.sh && ./tcp_old.sh
}

function installBBR2(){
    
    if [[ -f ./tcp.sh ]];  then
        mv ./tcp.sh ./tcp_old.sh
    fi    
    wget -N --no-check-certificate "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh" && chmod +x tcp.sh && ./tcp.sh
}



function installWireguard(){
    bash <(wget -qO- https://github.com/jinwyp/one_click_script/raw/master/install_kernel.sh)
    # wget -N --no-check-certificate https://github.com/jinwyp/one_click_script/raw/master/install_kernel.sh && chmod +x ./install_kernel.sh && ./install_kernel.sh
}


function installBTPanel(){
    if [ "$osRelease" == "centos" ]; then
        yum install -y wget && wget -O install.sh http://download.bt.cn/install/install_6.0.sh && sh install.sh
    else
        curl -sSO http://download.bt.cn/install/install_panel.sh && bash install_panel.sh

    fi
}

function installBTPanelCrack(){
    if [ "$osRelease" == "centos" ]; then
        yum install -y wget && wget -O install.sh https://download.fenhao.me/install/install_6.0.sh && sh install.sh
    else
        curl -sSO https://download.fenhao.me/install/install_panel.sh && bash install_panel.sh
    fi
}

function installBTPanelCrack2(){
    if [ "$osRelease" == "centos" ]; then
        yum install -y wget && wget -O install.sh http://download.hostcli.com/install/install_6.0.sh && sh install.sh
    else
        exit
    fi
}




configNetworkRealIp=""
configNetworkLocalIp=""
configSSLDomain=""

configSSLAcmeScriptPath="${HOME}/.acme.sh"
configWebsiteFatherPath="${HOME}/website"
configSSLCertBakPath="${HOME}/sslbackup"
configSSLCertPath="${HOME}/website/cert"
configSSLCertKeyFilename="private.key"
configSSLCertFullchainFilename="fullchain.cer"
configWebsitePath="${HOME}/website/html"
configTrojanWindowsCliPrefixPath=$(cat /dev/urandom | head -1 | md5sum | head -c 20)
configWebsiteDownloadPath="${configWebsitePath}/download/${configTrojanWindowsCliPrefixPath}"
configDownloadTempPath="${HOME}/temp"

configRanPath="${HOME}/ran"


versionTrojan="1.16.0"
downloadFilenameTrojan="trojan-${versionTrojan}-linux-amd64.tar.xz"

versionTrojanGo="0.10.4"
downloadFilenameTrojanGo="trojan-go-linux-amd64.zip"

versionV2ray="4.40.1"
downloadFilenameV2ray="v2ray-linux-64.zip"

versionXray="1.4.2"
downloadFilenameXray="Xray-linux-64.zip"

versionTrojanWeb="2.10.5"
downloadFilenameTrojanWeb="trojan-linux-amd64"

promptInfoTrojanName=""
isTrojanGo="no"
isTrojanGoSupportWebsocket="false"
configTrojanGoWebSocketPath=$(cat /dev/urandom | head -1 | md5sum | head -c 8)
configTrojanPasswordPrefixInput="jin"

configTrojanPath="${HOME}/trojan"
configTrojanGoPath="${HOME}/trojan-go"
configTrojanWebPath="${HOME}/trojan-web"
configTrojanLogFile="${HOME}/trojan-access.log"
configTrojanGoLogFile="${HOME}/trojan-go-access.log"

configTrojanBasePath=${configTrojanPath}
configTrojanBaseVersion=${versionTrojan}

configTrojanWebNginxPath=$(cat /dev/urandom | head -1 | md5sum | head -c 5)
configTrojanWebPort="$(($RANDOM + 10000))"


isInstallNginx="true"
isNginxWithSSL="no"
nginxConfigPath="/etc/nginx/nginx.conf"
nginxAccessLogFilePath="${HOME}/nginx-access.log"
nginxErrorLogFilePath="${HOME}/nginx-error.log"

promptInfoXrayInstall="V2ray"
promptInfoXrayVersion=""
promptInfoXrayName="v2ray"
isXray="no"

configV2rayWebSocketPath=$(cat /dev/urandom | head -1 | md5sum | head -c 8)
configV2rayGRPCServiceName=$(cat /dev/urandom | head -1 | md5sum | head -c 8)
configV2rayPort="$(($RANDOM + 10000))"
configV2rayGRPCPort="$(($RANDOM + 10000))"
configV2rayVmesWSPort="$(($RANDOM + 10000))"
configV2rayVmessTCPPort="$(($RANDOM + 10000))"
configV2rayPortShowInfo=$configV2rayPort
configV2rayPortGRPCShowInfo=$configV2rayGRPCPort
configV2rayIsTlsShowInfo="tls"
configV2rayTrojanPort="$(($RANDOM + 10000))"

configV2rayPath="${HOME}/v2ray"
configV2rayAccessLogFilePath="${HOME}/v2ray-access.log"
configV2rayErrorLogFilePath="${HOME}/v2ray-error.log"
configV2rayProtocol="vmess"
configV2rayVlessMode=""
configV2rayWSorGrpc="ws"


configReadme=${HOME}/readme_trojan_v2ray.txt


function downloadAndUnzip(){
    if [ -z $1 ]; then
        green " ================================================== "
        green "     ????????????????????????!"
        green " ================================================== "
        exit
    fi
    if [ -z $2 ]; then
        green " ================================================== "
        green "     ????????????????????????!"
        green " ================================================== "
        exit
    fi
    if [ -z $3 ]; then
        green " ================================================== "
        green "     ??????????????????????????????!"
        green " ================================================== "
        exit
    fi

    mkdir -p ${configDownloadTempPath}

    if [[ $3 == *"tar.xz"* ]]; then
        green "===== ???????????????tar??????: $3 "
        wget -O ${configDownloadTempPath}/$3 $1
        tar xf ${configDownloadTempPath}/$3 -C ${configDownloadTempPath}
        mv ${configDownloadTempPath}/trojan/* $2
        rm -rf ${configDownloadTempPath}/trojan
    else
        green "===== ???????????????zip??????:  $3 "
        wget -O ${configDownloadTempPath}/$3 $1
        unzip -d $2 ${configDownloadTempPath}/$3
    fi

}

function getGithubLatestReleaseVersion(){
    # https://github.com/p4gefau1t/trojan-go/issues/63
    wget --no-check-certificate -qO- https://api.github.com/repos/$1/tags | grep 'name' | cut -d\" -f4 | head -1 | cut -b 2-
}

function getTrojanAndV2rayVersion(){
    # https://github.com/trojan-gfw/trojan/releases/download/v1.16.0/trojan-1.16.0-linux-amd64.tar.xz
    # https://github.com/p4gefau1t/trojan-go/releases/download/v0.8.1/trojan-go-linux-amd64.zip

    echo ""

    if [[ $1 == "trojan" ]] ; then
        versionTrojan=$(getGithubLatestReleaseVersion "trojan-gfw/trojan")
        downloadFilenameTrojan="trojan-${versionTrojan}-linux-amd64.tar.xz"
        echo "versionTrojan: ${versionTrojan}"
    fi

    if [[ $1 == "trojan-go" ]] ; then
        versionTrojanGo=$(getGithubLatestReleaseVersion "p4gefau1t/trojan-go")
        downloadFilenameTrojanGo="trojan-go-linux-amd64.zip"
        echo "versionTrojanGo: ${versionTrojanGo}"
    fi

    if [[ $1 == "v2ray" ]] ; then
        versionV2ray=$(getGithubLatestReleaseVersion "v2fly/v2ray-core")
        echo "versionV2ray: ${versionV2ray}"
    fi

    if [[ $1 == "xray" ]] ; then
        versionXray=$(getGithubLatestReleaseVersion "XTLS/Xray-core")
        echo "versionXray: ${versionXray}"
    fi

    if [[ $1 == "trojan-web" ]] ; then
        versionTrojanWeb=$(getGithubLatestReleaseVersion "Jrohy/trojan")
        downloadFilenameTrojanWeb="trojan-linux-amd64"
        echo "versionTrojanWeb: ${versionTrojanWeb}"
    fi

    if [[ $1 == "wgcf" ]] ; then
        versionWgcf=$(getGithubLatestReleaseVersion "ViRb3/wgcf")
        downloadFilenameWgcf="wgcf_${versionWgcf}_linux_amd64"
        echo "versionWgcf: ${versionWgcf}"
    fi

}

function stopServiceNginx(){
    serviceNginxStatus=`ps -aux | grep "nginx: worker" | grep -v "grep"`
    if [[ -n "$serviceNginxStatus" ]]; then
        ${sudoCmd} systemctl stop nginx.service
    fi
}

function stopServiceV2ray(){
    if [[ -f "${osSystemMdPath}v2ray.service" ]] || [[ -f "/etc/systemd/system/v2ray.service" ]] || [[ -f "/lib/systemd/system/v2ray.service" ]] ; then
        ${sudoCmd} systemctl stop v2ray.service
    fi
}

function isTrojanGoInstall(){
    if [ "$isTrojanGo" = "yes" ] ; then
        getTrojanAndV2rayVersion "trojan-go"
        configTrojanBaseVersion=${versionTrojanGo}
        configTrojanBasePath="${configTrojanGoPath}"
        promptInfoTrojanName="-go"
    else
        getTrojanAndV2rayVersion "trojan"
        configTrojanBaseVersion=${versionTrojan}
        configTrojanBasePath="${configTrojanPath}"
        promptInfoTrojanName=""
    fi
}


function compareRealIpWithLocalIp(){
    echo
    echo

    isDomainValidInput="n"

    if [[ $isDomainValidInput == [Yy] ]]; then
        if [ -n $1 ]; then
            configNetworkRealIp=`ping $1 -c 1 | sed '1{s/[^(]*(//;s/).*//;q}'`
            # configNetworkLocalIp=`curl ipv4.icanhazip.com`
            configNetworkLocalIp=`curl v4.ident.me`

            green " ================================================== "
            green "     ????????????????????? ${configNetworkRealIp}, ???VPS???IP??? ${configNetworkLocalIp}. "
            green " ================================================== "

            if [[ ${configNetworkRealIp} == ${configNetworkLocalIp} ]] ; then
                green " ================================================== "
                green "     ???????????????IP??????!"
                green " ================================================== "
                true
            else
                green " ================================================== "
                red "     ????????????????????????VPS IP???????????????!"
                red "     ????????????????????????????????????????????????, ??????????????????DNS????????????!"
                green " ================================================== "
                false
            fi
        else
            green " ================================================== "        
            red "     ??????????????????!"
            green " ================================================== "        
            false
        fi
        
    else
        green " ================================================== "
        green "     ?????????????????????????????????!"
        green " ================================================== "
        true
    fi
}




function getSSLByDifferentSite(){

    echo
    if [[ $1 == "webrootfolder" ]] ; then
        read -r -p "?????????Web????????????html?????????????????????? ??????/usr/share/nginx/html:" isDomainSSLNginxWebrootFolderInput
        echo "???????????????????????????????????? ${isDomainSSLNginxWebrootFolderInput}"

        if [ -z ${isDomainSSLNginxWebrootFolderInput} ]; then
            red "?????????Web???????????? html ?????????????????????????????????, ????????????????????????????????? ${HOME}/website/html, ???????????????web?????????????????????????????????!"
            configWebsitePath="${HOME}/website/html"
        else
            configWebsitePath="${isDomainSSLNginxWebrootFolderInput}"
        fi

    else
        configWebsitePath="${HOME}/website/html"
    fi


    echo
    isDomainSSLFromLetInput="y"

    if [[ $isDomainSSLFromLetInput == [Yy] ]]; then
        ${configSSLAcmeScriptPath}/acme.sh --issue -d ${configSSLDomain} --webroot ${configWebsitePath} --keylength ec-256 --server letsencrypt
        
    else
        read -p "?????????????????????, ??????BuyPass.com????????????:" isDomainSSLFromBuyPassEmailInput
        isDomainSSLFromBuyPassEmailInput=${isDomainSSLFromBuyPassEmailInput:-test@gmail.com}

        echo
        ${configSSLAcmeScriptPath}/acme.sh --server https://api.buypass.com/acme/directory --register-account  --accountemail ${isDomainSSLFromBuyPassEmailInput}
        
        echo
        ${configSSLAcmeScriptPath}/acme.sh --server https://api.buypass.com/acme/directory --days 170 --issue -d ${configSSLDomain} --webroot ${configWebsitePath}  --keylength ec-256
    fi

    echo
    ${configSSLAcmeScriptPath}/acme.sh --installcert --ecc -d ${configSSLDomain} \
    --key-file ${configSSLCertPath}/${configSSLCertKeyFilename} \
    --fullchain-file ${configSSLCertPath}/${configSSLCertFullchainFilename} \
    --reloadcmd "systemctl restart nginx.service"

}



function getHTTPSCertificate(){

    # ??????https??????
	mkdir -p ${configSSLCertPath}
	mkdir -p ${configWebsitePath}
	curl https://get.acme.sh | sh

    echo
    isSSLRequestMethodHttpInput="y"

    echo
    if [[ $isSSLRequestMethodHttpInput == [Yy] ]]; then

        if [[ $1 == "standalone" ]] ; then
            green "  ??????????????????, acme.sh ?????? http standalone mode ?????? "
            echo

            ${configSSLAcmeScriptPath}/acme.sh --issue --standalone -d ${configSSLDomain}  --keylength ec-256 --server letsencrypt
            echo

            ${configSSLAcmeScriptPath}/acme.sh --installcert --ecc -d ${configSSLDomain} \
            --key-file ${configSSLCertPath}/${configSSLCertKeyFilename} \
            --fullchain-file ${configSSLCertPath}/${configSSLCertFullchainFilename} \
            --reloadcmd "systemctl restart nginx.service"
        
        elif [[ $1 == "webroot" ]] ; then
            green "  ??????????????????, acme.sh ?????? http webroot mode ??????, ????????? web???????????????nginx ???????????????80?????? "
            getSSLByDifferentSite "webrootfolder"

        else
            # https://github.com/m3ng9i/ran/issues/10

            mkdir -p ${configRanPath}
            
            if [[ -f "${configRanPath}/ran_linux_amd64" ]]; then
                echo
            else
                downloadAndUnzip "https://github.com/m3ng9i/ran/releases/download/v0.1.5/ran_linux_amd64.zip" "${configRanPath}" "ran_linux_amd64.zip" 
                chmod +x ${configRanPath}/ran_linux_amd64
            fi    

            echo
            echo "nohup ${configRanPath}/ran_linux_amd64 -l=false -g=false -sa=true -p=80 -r=${configWebsitePath} >/dev/null 2>&1 &"
            nohup ${configRanPath}/ran_linux_amd64 -l=false -g=false -sa=true -p=80 -r=${configWebsitePath} >/dev/null 2>&1 &
            echo
            
            green "  ??????????????????, acme.sh ?????? http webroot mode ??????, ????????? ran ???????????????web????????? "
            getSSLByDifferentSite

            sleep 4
            ps -C ran_linux_amd64 -o pid= | xargs -I {} kill {}

        fi
        
    else
        green "  ??????????????????, acme.sh ?????? dns mode ?????? "
        echo
        read -r -p "?????????????????????Email ????????? ZeroSSL.com ??????SSL??????:" isSSLDNSEmailInput
        ${configSSLAcmeScriptPath}/acme.sh --register-account  -m ${isSSLDNSEmailInput} --server zerossl

        echo
        green "????????? DNS provider DNS ?????????: 1. CloudFlare, 2. AliYun, 3. DNSPod(Tencent) "
        red "?????? CloudFlare ?????????????????????????????????.tk .cf ???  ??????????????????API ??????DNS?????? "
        read -r -p "????????? DNS ????????? ? ????????????????????? 1. CloudFlare, ??????????????????:" isSSLDNSProviderInput
        isSSLDNSProviderInput=${isSSLDNSProviderInput:-1}    

        
        if [ "$isSSLDNSProviderInput" == "1" ]; then
            read -r -p "Please Input CloudFlare Email: " cf_email
            export CF_Email="${cf_email}"
            read -r -p "Please Input CloudFlare Global API Key: " cf_key
            export CF_Key="${cf_key}"

            ${configSSLAcmeScriptPath}/acme.sh --issue -d "${configSSLDomain}" --dns dns_cf --force --keylength ec-256 --server zerossl --debug 

        elif [ "$isSSLDNSProviderInput" == "2" ]; then
            read -r -p "Please Input Ali Key: " Ali_Key
            export Ali_Key="${Ali_Key}"
            read -r -p "Please Input Ali Secret: " Ali_Secret
            export Ali_Secret="${Ali_Secret}"

            ${configSSLAcmeScriptPath}/acme.sh --issue -d "${configSSLDomain}" --dns dns_ali --force --keylength ec-256 --server zerossl --debug 

        elif [ "$isSSLDNSProviderInput" == "3" ]; then
            read -r -p "Please Input DNSPod ID: " DP_Id
            export DP_Id="${DP_Id}"
            read -r -p "Please Input DNSPod Key: " DP_Key
            export DP_Key="${DP_Key}"

            ${configSSLAcmeScriptPath}/acme.sh --issue -d "${configSSLDomain}" --dns dns_dp --force --keylength ec-256 --server zerossl --debug 
        fi

        ${configSSLAcmeScriptPath}/acme.sh --installcert --ecc -d ${configSSLDomain} \
        --key-file ${configSSLCertPath}/${configSSLCertKeyFilename} \
        --fullchain-file ${configSSLCertPath}/${configSSLCertFullchainFilename} \
        --reloadcmd "systemctl restart nginx.service"

    fi

    green " ================================================== "
}



function installWebServerNginx(){

    green " ================================================== "
    yellow "     ???????????? Web????????? nginx !"
    green " ================================================== "

    if test -s ${nginxConfigPath}; then
        green " ================================================== "
        red "     Nginx ?????????, ????????????!"
        green " ================================================== "
        exit
    fi

    stopServiceV2ray
    
    ${osSystemPackage} install nginx -y
    ${sudoCmd} systemctl enable nginx.service
    ${sudoCmd} systemctl stop nginx.service

    if [[ -z $1 ]] ; then
        cat > "${nginxConfigPath}" <<-EOF
user  root;
worker_processes  1;
error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;
events {
    worker_connections  1024;
}
http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    log_format  main  '\$remote_addr - \$remote_user [\$time_local] '
                      '"\$request" \$status \$body_bytes_sent  '
                      '"\$http_referer" "\$http_user_agent" "\$http_x_forwarded_for"';
    access_log  $nginxAccessLogFilePath  main;
    error_log $nginxErrorLogFilePath;

    sendfile        on;
    #tcp_nopush     on;
    keepalive_timeout  120;
    client_max_body_size 20m;
    gzip  on;

    server {
        listen       80;
        server_name  $configSSLDomain;
        root $configWebsitePath;
        index index.php index.html index.htm;

        location /$configV2rayWebSocketPath {
            proxy_pass http://127.0.0.1:$configV2rayPort;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$http_host;

            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        }
    }
}
EOF

    elif [[ $1 == "trojan-web" ]] ; then

        cat > "${nginxConfigPath}" <<-EOF
user  root;
worker_processes  1;
error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;
events {
    worker_connections  1024;
}
http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    log_format  main  '\$remote_addr - \$remote_user [\$time_local] '
                      '"\$request" \$status \$body_bytes_sent  '
                      '"\$http_referer" "\$http_user_agent" "\$http_x_forwarded_for"';
    access_log  $nginxAccessLogFilePath  main;
    error_log $nginxErrorLogFilePath;

    sendfile        on;
    #tcp_nopush     on;
    keepalive_timeout  120;
    client_max_body_size 20m;
    #gzip on;

    server {
        listen       80;
        server_name  $configSSLDomain;
        root $configWebsitePath;
        index index.php index.html index.htm;

        location /$configTrojanWebNginxPath {
            proxy_pass http://127.0.0.1:$configTrojanWebPort/;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Host \$http_host;
        }

        location ~* ^/(static|common|auth|trojan)/ {
            proxy_pass  http://127.0.0.1:$configTrojanWebPort;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$http_host;
        }

        # http redirect to https
        if ( \$remote_addr != 127.0.0.1 ){
            rewrite ^/(.*)$ https://$configSSLDomain/\$1 redirect;
        }
    }
}
EOF
    else
        cat > "${nginxConfigPath}" <<-EOF
user  root;
worker_processes  1;
error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;
events {
    worker_connections  1024;
}
http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    log_format  main  '\$remote_addr - \$remote_user [\$time_local] '
                      '"\$request" \$status \$body_bytes_sent  '
                      '"\$http_referer" "\$http_user_agent" "\$http_x_forwarded_for"';
    access_log  $nginxAccessLogFilePath  main;
    error_log $nginxErrorLogFilePath;

    sendfile        on;
    #tcp_nopush     on;
    keepalive_timeout  120;
    client_max_body_size 20m;
    gzip  on;

    server {
        listen 443 ssl http2;
        listen [::]:443 http2;
        server_name  $configSSLDomain;

        ssl_certificate       ${configSSLCertPath}/$configSSLCertFullchainFilename;
        ssl_certificate_key   ${configSSLCertPath}/$configSSLCertKeyFilename;
        ssl_protocols         TLSv1.2 TLSv1.3;
        ssl_ciphers           TLS-AES-256-GCM-SHA384:TLS-CHACHA20-POLY1305-SHA256:TLS-AES-128-GCM-SHA256:TLS-AES-128-CCM-8-SHA256:TLS-AES-128-CCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256;

        # Config for 0-RTT in TLSv1.3
        ssl_early_data on;
        ssl_stapling on;
        ssl_stapling_verify on;
        add_header Strict-Transport-Security "max-age=31536000";
        
        root $configWebsitePath;
        index index.php index.html index.htm;

        location /$configV2rayWebSocketPath {
            proxy_pass http://127.0.0.1:$configV2rayPort;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$http_host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        }

        location /$configV2rayGRPCServiceName {
            grpc_pass grpc://127.0.0.1:$configV2rayGRPCPort;
            grpc_connect_timeout 60s;
            grpc_read_timeout 720m;
            grpc_send_timeout 720m;
            grpc_set_header X-Real-IP \$remote_addr;
            grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        }
    }

    server {
        listen 80;
        listen [::]:80;
        server_name  $configSSLDomain;
        return 301 https://$configSSLDomain\$request_uri;
    }
}
EOF
    fi



    # ?????????????????? ?????????????????????
    rm -rf ${configWebsitePath}/*
    mkdir -p ${configWebsiteDownloadPath}

    downloadAndUnzip "https://github.com/jinwyp/one_click_script/raw/master/download/website2.zip" "${configWebsitePath}" "website2.zip"

    wget -P "${configWebsiteDownloadPath}" "https://github.com/jinwyp/one_click_script/raw/master/download/trojan-mac.zip"
    wget -P "${configWebsiteDownloadPath}" "https://github.com/jinwyp/one_click_script/raw/master/download/v2ray-windows.zip" 
    wget -P "${configWebsiteDownloadPath}" "https://github.com/jinwyp/one_click_script/raw/master/download/v2ray-mac.zip"

    # downloadAndUnzip "https://github.com/jinwyp/one_click_script/raw/master/download/trojan_client_all.zip" "${configWebsiteDownloadPath}" "trojan_client_all.zip"
    # downloadAndUnzip "https://github.com/jinwyp/one_click_script/raw/master/download/trojan-qt5.zip" "${configWebsiteDownloadPath}" "trojan-qt5.zip"
    # downloadAndUnzip "https://github.com/jinwyp/one_click_script/raw/master/download/v2ray_client_all.zip" "${configWebsiteDownloadPath}" "v2ray_client_all.zip"

    #wget -P "${configWebsiteDownloadPath}" "https://github.com/jinwyp/one_click_script/raw/master/download/v2ray-android.zip"

    ${sudoCmd} systemctl start nginx.service

    green " ================================================== "
    green "       Web????????? nginx ????????????!!"
    green "    ??????????????? http://${configSSLDomain}"

	if [[ $1 == "trojan-web" ]] ; then
	    yellow "    Trojan-web ${versionTrojanWeb} ???????????????????????????  http://${configSSLDomain}/${configTrojanWebNginxPath} "
	    green "    Trojan-web ????????????????????? ????????????????????? ${configTrojanWebPath}/trojan-web"
	    green "    Trojan ????????????????????????????????? /usr/bin/trojan/trojan"
	    green "    Trojan ???????????????????????? /usr/local/etc/trojan/config.json "
	    green "    Trojan-web ????????????: systemctl stop trojan-web.service  ????????????: systemctl start trojan-web.service  ????????????: systemctl restart trojan-web.service"
	    green "    Trojan ????????????: systemctl stop trojan.service  ????????????: systemctl start trojan.service  ????????????: systemctl restart trojan.service"
	fi

    green "    ?????????????????????html????????????????????? ${configWebsitePath}, ???????????????????????????!"
	red "    nginx ???????????? ${nginxConfigPath} "
	green "    nginx ???????????? ${nginxAccessLogFilePath} "
	green "    nginx ???????????? ${nginxErrorLogFilePath} "
    green "    nginx ??????????????????: journalctl -n 50 -u nginx.service"
	green "    nginx ????????????: systemctl start nginx.service  ????????????: systemctl stop nginx.service  ????????????: systemctl restart nginx.service"
	green "    nginx ????????????????????????: systemctl status nginx.service "

    green " ================================================== "

    cat >> ${configReadme} <<-EOF

Web????????? nginx ????????????! ??????????????? ${configSSLDomain}   
?????????????????????html????????????????????? ${configWebsitePath}, ???????????????????????????.
nginx ???????????? ${nginxConfigPath}
nginx ???????????? ${nginxAccessLogFilePath}
nginx ???????????? ${nginxErrorLogFilePath}

nginx ??????????????????: journalctl -n 50 -u nginx.service

nginx ????????????: systemctl start nginx.service  
nginx ????????????: systemctl stop nginx.service  
nginx ????????????: systemctl restart nginx.service
nginx ????????????????????????: systemctl status nginx.service


EOF

	if [[ $1 == "trojan-web" ]] ; then
        cat >> ${configReadme} <<-EOF

?????????Trojan-web ${versionTrojanWeb} ?????????????????????,????????????  ${configSSLDomain}/${configTrojanWebNginxPath}
Trojan-web ????????????: systemctl stop trojan-web.service  ????????????: systemctl start trojan-web.service  ????????????: systemctl restart trojan-web.service

EOF
	fi

}

function removeNginx(){

    ${sudoCmd} systemctl stop nginx.service

    echo
    green " ================================================== "
    red " ????????????????????????nginx"
    green " ================================================== "
    echo

    if [ "$osRelease" == "centos" ]; then
        yum remove -y nginx
    else
        apt autoremove -y --purge nginx nginx-common nginx-core
        apt-get remove --purge nginx nginx-full nginx-common nginx-core
    fi


    rm -rf ${configSSLCertBakPath}
    mkdir -p ${configSSLCertBakPath}
    cp -f ${configSSLCertPath}/* ${configSSLCertBakPath}

    rm -rf ${configWebsiteFatherPath}
    rm -f ${nginxAccessLogFilePath}
    rm -f ${nginxErrorLogFilePath}

    rm -f ${configReadme}

    rm -rf "/etc/nginx"
    
    
    rm -rf ${configDownloadTempPath}

    read -p "?????????????????? ??? ??????acme.sh??????????????????, ??????????????????????????????????????????, ???????????????????????????,  ?????????[y/N]:" isDomainSSLRemoveInput
    isDomainSSLRemoveInput=${isDomainSSLRemoveInput:-n}

    echo
    green " ================================================== "
    if [[ $isDomainSSLRemoveInput == [Yy] ]]; then
        ${sudoCmd} bash ${configSSLAcmeScriptPath}/acme.sh --uninstall
        # uninstall ${configSSLAcmeScriptPath}
        green "  Nginx ????????????, SSL ?????????????????????!"
        
    else
        mkdir -p ${configSSLCertPath}
        cp -f ${configSSLCertBakPath}/* ${configSSLCertPath}
        green "  Nginx ????????????, ????????? SSL ???????????? ??? ${configSSLCertPath} "
    fi

    rm -rf ${configSSLCertBakPath}
    green " ================================================== "
    echo
}


function installTrojanV2rayWithNginx(){

    green " ================================================== "
    yellow " ?????????????????????VPS????????? ??????www.xxx.com: (??????????????????CDN?????????)"
    if [[ $1 == "repair" ]] ; then
        blue " ???????????????????????????????????????????????????"
    fi
    green " ================================================== "

    read configSSLDomain

    stopServiceNginx
    testLinuxPortUsage
    installPackage

    isDomainSSLRequestInput="Y"

    if compareRealIpWithLocalIp "${configSSLDomain}" ; then
        if [[ $isDomainSSLRequestInput == [Yy] ]]; then
            getHTTPSCertificate 
        else
            green " =================================================="
            green " ????????????????????????, ??????????????????????????????, ???????????????trojan???v2ray??????!"
            green " ${configSSLDomain} ?????????????????????????????? ${configSSLCertPath}/${configSSLCertFullchainFilename} "
            green " ${configSSLDomain} ?????????????????????????????? ${configSSLCertPath}/${configSSLCertKeyFilename} "
            green " =================================================="
        fi
    else
        exit
    fi


    if test -s ${configSSLCertPath}/${configSSLCertFullchainFilename}; then
        green " ================================================== "
        green "     SSL?????? ????????????????????????!"
        green " ================================================== "

        if [ "$isNginxWithSSL" = "no" ] ; then
            installWebServerNginx
        else
            installWebServerNginx "v2ray"
        fi

        if [ -z $1 ]; then
            installTrojanServer
        elif [ $1 = "both" ]; then
            installTrojanServer
            installV2ray
        else
            installV2ray
        fi
    else
        red " ================================================== "
        red " https???????????????????????????????????????!"
        red " ??????????????????DNS????????????, ??????????????????????????????????????????!"
        red " ?????????80???443??????????????????, VPS?????????????????????????????????????????????????????????????????????????????????!"
        red " ??????VPS, ??????????????????, ??????????????????????????????????????? ! "
        red " ================================================== "
        exit
    fi    
}


function installTrojanServer(){

    trojanPassword1="Aa112211"
    trojanPassword2=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword3=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword4=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword5=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword6=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword7=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword8=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword9=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword10=$(cat /dev/urandom | head -1 | md5sum | head -c 10)

    isTrojanGoInstall

    if [[ -f "${configTrojanBasePath}/trojan${promptInfoTrojanName}" ]]; then
        green " =================================================="
        green "  ???????????? Trojan${promptInfoTrojanName} , ???????????? !"
        green " =================================================="
        exit
    fi


    configTrojanPasswordPrefixInput=""


    if [ "$configV2rayVlessMode" != "trojan" ] ; then
        configV2rayTrojanPort=443

        inputV2rayServerPort "textMainTrojanPort"
        configV2rayTrojanPort=${isTrojanUserPortInput}         
    fi

    mkdir -p ${configTrojanBasePath}
    cd ${configTrojanBasePath}
    rm -rf ${configTrojanBasePath}/*

    if [ "$isTrojanGo" = "no" ] ; then
        # https://github.com/trojan-gfw/trojan/releases/download/v1.16.0/trojan-1.16.0-linux-amd64.tar.xz
        downloadAndUnzip "https://github.com/trojan-gfw/trojan/releases/download/v${versionTrojan}/${downloadFilenameTrojan}" "${configTrojanPath}" "${downloadFilenameTrojan}"
    else
        # https://github.com/p4gefau1t/trojan-go/releases/download/v0.8.1/trojan-go-linux-amd64.zip
        downloadAndUnzip "https://github.com/p4gefau1t/trojan-go/releases/download/v${versionTrojanGo}/${downloadFilenameTrojanGo}" "${configTrojanGoPath}" "${downloadFilenameTrojanGo}"
    fi





    read -r -d '' trojanConfigUserpasswordInput << EOM
        "${trojanPassword1}",
        "${trojanPassword2}",
        "${trojanPassword3}",
        "${trojanPassword4}",
        "${trojanPassword5}",
        "${trojanPassword6}",
        "${trojanPassword7}",
        "${trojanPassword8}",
        "${trojanPassword9}",
        "${trojanPassword10}",
        "${configTrojanPasswordPrefixInput}202001",
        "${configTrojanPasswordPrefixInput}202002",
        "${configTrojanPasswordPrefixInput}202003",
        "${configTrojanPasswordPrefixInput}202004",
        "${configTrojanPasswordPrefixInput}202005",
        "${configTrojanPasswordPrefixInput}202006",
        "${configTrojanPasswordPrefixInput}202007",
        "${configTrojanPasswordPrefixInput}202008",
        "${configTrojanPasswordPrefixInput}202009",
        "${configTrojanPasswordPrefixInput}202010",
        "${configTrojanPasswordPrefixInput}202011",
        "${configTrojanPasswordPrefixInput}202012",
        "${configTrojanPasswordPrefixInput}202013",
        "${configTrojanPasswordPrefixInput}202014",
        "${configTrojanPasswordPrefixInput}202015",
        "${configTrojanPasswordPrefixInput}202016",
        "${configTrojanPasswordPrefixInput}202017",
        "${configTrojanPasswordPrefixInput}202018",
        "${configTrojanPasswordPrefixInput}202019",
        "${configTrojanPasswordPrefixInput}202020"
EOM


    if [ "$isTrojanGo" = "no" ] ; then

        # ??????trojan ??????????????????
	    cat > ${configTrojanBasePath}/server.json <<-EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": $configV2rayTrojanPort,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": [
        ${trojanConfigUserpasswordInput}
    ],
    "log_level": 1,
    "ssl": {
        "cert": "${configSSLCertPath}/$configSSLCertFullchainFilename",
        "key": "${configSSLCertPath}/$configSSLCertKeyFilename",
        "key_password": "",
        "cipher_tls13":"TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
	    "prefer_server_cipher": true,
        "alpn": [
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": false,
        "session_timeout": 600,
        "plain_http_response": "",
        "curves": "",
        "dhparam": ""
    },
    "tcp": {
        "no_delay": true,
        "keep_alive": true,
        "fast_open": false,
        "fast_open_qlen": 20
    },
    "mysql": {
        "enabled": false,
        "server_addr": "127.0.0.1",
        "server_port": 3306,
        "database": "trojan",
        "username": "trojan",
        "password": ""
    }
}
EOF

        # rm /etc/systemd/system/trojan.service   
        # ??????????????????
        cat > ${osSystemMdPath}trojan.service <<-EOF
[Unit]
Description=trojan
After=network.target

[Service]
Type=simple
PIDFile=${configTrojanPath}/trojan.pid
ExecStart=${configTrojanPath}/trojan -l ${configTrojanLogFile} -c "${configTrojanPath}/server.json"
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
RestartPreventExitStatus=23
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    fi


    if [ "$isTrojanGo" = "yes" ] ; then

        # ??????trojan ??????????????????
	    cat > ${configTrojanBasePath}/server.json <<-EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": $configV2rayTrojanPort,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": [
        ${trojanConfigUserpasswordInput}
    ],
    "log_level": 1,
    "log_file": "${configTrojanGoLogFile}",
    "ssl": {
        "verify": true,
        "verify_hostname": true,
        "cert": "${configSSLCertPath}/$configSSLCertFullchainFilename",
        "key": "${configSSLCertPath}/$configSSLCertKeyFilename",
        "key_password": "",
        "curves": "",
        "cipher": "",        
	    "prefer_server_cipher": false,
        "sni": "${configSSLDomain}",
        "alpn": [
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": true,
        "plain_http_response": "",
        "fallback_addr": "127.0.0.1",
        "fallback_port": 80,    
        "fingerprint": "firefox"
    },
    "tcp": {
        "no_delay": true,
        "keep_alive": true
    },
    "websocket": {
        "enabled": ${isTrojanGoSupportWebsocket},
        "path": "/${configTrojanGoWebSocketPath}",
        "host": "${configSSLDomain}"
    },
    "mysql": {
        "enabled": false,
        "server_addr": "127.0.0.1",
        "server_port": 3306,
        "database": "trojan",
        "username": "trojan",
        "password": ""
    }
}
EOF

        # ??????????????????
        cat > ${osSystemMdPath}trojan-go.service <<-EOF
[Unit]
Description=trojan-go
After=network.target

[Service]
Type=simple
PIDFile=${configTrojanGoPath}/trojan-go.pid
ExecStart=${configTrojanGoPath}/trojan-go -config "${configTrojanGoPath}/server.json"
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF
    fi

    ${sudoCmd} chmod +x ${osSystemMdPath}trojan${promptInfoTrojanName}.service
    ${sudoCmd} systemctl daemon-reload
    ${sudoCmd} systemctl start trojan${promptInfoTrojanName}.service
    ${sudoCmd} systemctl enable trojan${promptInfoTrojanName}.service


    if [ "$configV2rayVlessMode" != "trojan" ] ; then
        
    
    # ??????????????? trojan windows ?????????????????????????????????
    rm -rf ${configTrojanBasePath}/trojan-win-cli
    rm -rf ${configTrojanBasePath}/trojan-win-cli-temp
    mkdir -p ${configTrojanBasePath}/trojan-win-cli-temp

    downloadAndUnzip "https://github.com/jinwyp/one_click_script/raw/master/download/trojan-win-cli.zip" "${configTrojanBasePath}" "trojan-win-cli.zip"

    if [ "$isTrojanGo" = "no" ] ; then
        downloadAndUnzip "https://github.com/trojan-gfw/trojan/releases/download/v${versionTrojan}/trojan-${versionTrojan}-win.zip" "${configTrojanBasePath}/trojan-win-cli-temp" "trojan-${versionTrojan}-win.zip"
        mv -f ${configTrojanBasePath}/trojan-win-cli-temp/trojan/trojan.exe ${configTrojanBasePath}/trojan-win-cli/
        mv -f ${configTrojanBasePath}/trojan-win-cli-temp/trojan/VC_redist.x64.exe ${configTrojanBasePath}/trojan-win-cli/
    fi

    if [ "$isTrojanGo" = "yes" ] ; then
        downloadAndUnzip "https://github.com/p4gefau1t/trojan-go/releases/download/v${versionTrojanGo}/trojan-go-windows-amd64.zip" "${configTrojanBasePath}/trojan-win-cli-temp" "trojan-go-windows-amd64.zip"
        mv -f ${configTrojanBasePath}/trojan-win-cli-temp/* ${configTrojanBasePath}/trojan-win-cli/
    fi

    rm -rf ${configTrojanBasePath}/trojan-win-cli-temp
    cp ${configSSLCertPath}/${configSSLCertFullchainFilename} ${configTrojanBasePath}/trojan-win-cli/${configSSLCertFullchainFilename}

    cat > ${configTrojanBasePath}/trojan-win-cli/config.json <<-EOF
{
    "run_type": "client",
    "local_addr": "127.0.0.1",
    "local_port": 1080,
    "remote_addr": "${configSSLDomain}",
    "remote_port": 443,
    "password": [
        "${trojanPassword1}"
    ],
    "log_level": 1,
    "ssl": {
        "verify": true,
        "verify_hostname": true,
        "cert": "$configSSLCertFullchainFilename",
        "cipher_tls13":"TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
	    "sni": "",
        "alpn": [
            "h2",
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": false,
        "curves": ""
    },
    "tcp": {
        "no_delay": true,
        "keep_alive": true,
        "fast_open": false,
        "fast_open_qlen": 20
    }
}
EOF

    zip -r ${configWebsiteDownloadPath}/trojan-win-cli.zip ${configTrojanBasePath}/trojan-win-cli/

    fi



    # ?????? cron ????????????
    # https://stackoverflow.com/questions/610839/how-can-i-programmatically-create-a-new-cron-job

    # (crontab -l 2>/dev/null | grep -v '^[a-zA-Z]'; echo "15 4 * * 0,1,2,3,4,5,6 systemctl restart trojan.service") | sort - | uniq - | crontab -
    (crontab -l ; echo "10 4 * * 0,1,2,3,4,5,6 systemctl restart trojan${promptInfoTrojanName}.service") | sort - | uniq - | crontab -


	green "======================================================================"
	green "    Trojan${promptInfoTrojanName} Version: ${configTrojanBaseVersion} ???????????? !"

    if [[ ${isInstallNginx} == "true" ]]; then
        green "    ??????????????? https://${configSSLDomain}"
	    green "    ?????????????????????html????????????????????? ${configWebsitePath}, ???????????????????????????!"
    fi

	red "    Trojan${promptInfoTrojanName} ???????????????????????? ${configTrojanBasePath}/server.json "
	red "    Trojan${promptInfoTrojanName} ????????????????????????: ${configTrojanLogFile} "
	green "    Trojan${promptInfoTrojanName} ??????????????????: journalctl -n 50 -u trojan${promptInfoTrojanName}.service "

	green "    Trojan${promptInfoTrojanName} ????????????: systemctl stop trojan${promptInfoTrojanName}.service  ????????????: systemctl start trojan${promptInfoTrojanName}.service  ????????????: systemctl restart trojan${promptInfoTrojanName}.service"
	green "    Trojan${promptInfoTrojanName} ????????????????????????:  systemctl status trojan${promptInfoTrojanName}.service "
	green "    Trojan${promptInfoTrojanName} ????????? ?????????????????????, ??????????????????. ?????? crontab -l ?????? ???????????????????????? !"
	green "======================================================================"
	blue  "----------------------------------------"
	yellow "Trojan${promptInfoTrojanName} ??????????????????, ?????????????????????, ?????????????????? !"
	yellow "???????????????: ${configSSLDomain}  ??????: $configV2rayTrojanPort"
	yellow "??????1: ${trojanPassword1}"
	yellow "??????2: ${trojanPassword2}"
	yellow "??????3: ${trojanPassword3}"
	yellow "??????4: ${trojanPassword4}"
	yellow "??????5: ${trojanPassword5}"
	yellow "??????6: ${trojanPassword6}"
	yellow "??????7: ${trojanPassword7}"
	yellow "??????8: ${trojanPassword8}"
	yellow "??????9: ${trojanPassword9}"
	yellow "????????????10: ${trojanPassword10}"
	yellow "???????????????????????????20???: ??? ${configTrojanPasswordPrefixInput}202001 ??? ${configTrojanPasswordPrefixInput}202020 ???????????????"
	yellow "??????: ??????:${configTrojanPasswordPrefixInput}202002 ??? ??????:${configTrojanPasswordPrefixInput}202019 ???????????????"

    if [[ ${isTrojanGoSupportWebsocket} == "true" ]]; then
        yellow "Websocket path ?????????: /${configTrojanGoWebSocketPath}"
        # yellow "Websocket obfuscation_password ???????????????: ${trojanPasswordWS}"
        yellow "Websocket ??????TLS???: true ??????"
    fi

    echo
    green "======================================================================"
    yellow " Trojan${promptInfoTrojanName} ????????? Shadowrocket ????????????"

    if [ "$isTrojanGo" = "yes" ] ; then
        if [[ ${isTrojanGoSupportWebsocket} == "true" ]]; then
            green " trojan://${trojanPassword1}@${configSSLDomain}:${configV2rayTrojanPort}?peer=${configSSLDomain}&sni=${configSSLDomain}&plugin=obfs-local;obfs=websocket;obfs-host=${configSSLDomain};obfs-uri=/${configTrojanGoWebSocketPath}#${configSSLDomain}_trojan_go_ws"
            echo
            yellow " ????????? Trojan${promptInfoTrojanName} "
		    green "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3a%2f%2f${trojanPassword1}%40${configSSLDomain}%3a${configV2rayTrojanPort}%3fallowInsecure%3d0%26peer%3d${configSSLDomain}%26plugin%3dobfs-local%3bobfs%3dwebsocket%3bobfs-host%3d${configSSLDomain}%3bobfs-uri%3d/${configTrojanGoWebSocketPath}%23${configSSLDomain}_trojan_go_ws"

            echo
            yellow " Trojan${promptInfoTrojanName} QV2ray ????????????"
            green " trojan-go://${trojanPassword1}@${configSSLDomain}:${configV2rayTrojanPort}?sni=${configSSLDomain}&type=ws&host=${configSSLDomain}&path=%2F${configTrojanGoWebSocketPath}#${configSSLDomain}_trojan_go_ws"
        
        else
            green " trojan://${trojanPassword1}@${configSSLDomain}:${configV2rayTrojanPort}?peer=${configSSLDomain}&sni=${configSSLDomain}#${configSSLDomain}_trojan_go"
            echo
            yellow " ????????? Trojan${promptInfoTrojanName} "
            green "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3a%2f%2f${trojanPassword1}%40${configSSLDomain}%3a${configV2rayTrojanPort}%3fpeer%3d${configSSLDomain}%26sni%3d${configSSLDomain}%23${configSSLDomain}_trojan_go"

            echo
            yellow " Trojan${promptInfoTrojanName} QV2ray ????????????"
            green " trojan-go://${trojanPassword1}@${configSSLDomain}:${configV2rayTrojanPort}?sni=${configSSLDomain}&type=original&host=${configSSLDomain}#${configSSLDomain}_trojan_go"
        fi

    else
        green " trojan://${trojanPassword1}@${configSSLDomain}:${configV2rayTrojanPort}?peer=${configSSLDomain}&sni=${configSSLDomain}#${configSSLDomain}_trojan"
        echo
        yellow " ????????? Trojan${promptInfoTrojanName} "
		green "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3a%2f%2f${trojanPassword1}%40${configSSLDomain}%3a${configV2rayTrojanPort}%3fpeer%3d${configSSLDomain}%26sni%3d${configSSLDomain}%23${configSSLDomain}_trojan"

    fi

	echo
	green "======================================================================"
	green "??????????????????trojan?????????:"
	yellow "1 Windows ??????????????????http://${configSSLDomain}/download/${configTrojanWindowsCliPrefixPath}/v2ray-windows.zip"
	#yellow "  Windows ?????????????????????????????????http://${configSSLDomain}/download/${configTrojanWindowsCliPrefixPath}/trojan-Qt5-windows.zip"
	yellow "  Windows ?????????????????????????????????http://${configSSLDomain}/download/${configTrojanWindowsCliPrefixPath}/trojan-win-cli.zip"
	yellow "  Windows ??????????????????????????????????????????????????????????????????switchyomega???! "
    yellow "2 MacOS ??????????????????http://${configSSLDomain}/download/${configTrojanWindowsCliPrefixPath}/v2ray-mac.zip"
    yellow "  MacOS ???????????????????????????http://${configSSLDomain}/download/${configTrojanWindowsCliPrefixPath}/trojan-mac.zip"
    #yellow "  MacOS ?????????Trojan-Qt5?????????http://${configSSLDomain}/download/${configTrojanWindowsCliPrefixPath}/trojan-Qt5-mac.zip"
    yellow "3 Android ??????????????? https://github.com/trojan-gfw/igniter/releases "
    yellow "  Android ???????????????????????? https://github.com/2dust/v2rayNG/releases "
    yellow "  Android ?????????Clash?????? https://github.com/Kr328/ClashForAndroid/releases "
    yellow "4 iOS ????????? ?????????????????? https://shadowsockshelp.github.io/ios/ "
    yellow "  iOS ????????????????????????????????? https://lueyingpro.github.io/shadowrocket/index.html "
    yellow "  iOS ??????????????????????????? ?????? https://github.com/shadowrocketHelp/help/ "
    green "======================================================================"
	green "?????????????????????:"
	green "?????? https://www.v2rayssr.com/trojan-1.html ??? ?????? ??????????????? ????????? ?????????"
	green "??????????????? https://tlanyan.me/trojan-clients-download ??? ?????? trojan?????????"
    green "?????? https://westworldss.com/portal/page/download ??? ?????? ????????? ?????????"
	green "======================================================================"
	green "?????? Windows ?????????:"
	green "https://github.com/TheWanderingCoel/Trojan-Qt5/releases (exe???Win?????????, dmg???Mac?????????)"
	green "https://github.com/Qv2ray/Qv2ray/releases (exe???Win?????????, dmg???Mac?????????)"
	green "https://github.com/Dr-Incognito/V2Ray-Desktop/releases (exe???Win?????????, dmg???Mac?????????)"
	green "https://github.com/Fndroid/clash_for_windows_pkg/releases"
	green "======================================================================"
	green "?????? Mac ?????????:"
	green "https://github.com/TheWanderingCoel/Trojan-Qt5/releases (exe???Win?????????, dmg???Mac?????????)"
	green "https://github.com/Qv2ray/Qv2ray/releases (exe???Win?????????, dmg???Mac?????????)"
	green "https://github.com/Dr-Incognito/V2Ray-Desktop/releases (exe???Win?????????, dmg???Mac?????????)"
	green "https://github.com/JimLee1996/TrojanX/releases (exe???Win?????????, dmg???Mac?????????)"
	green "https://github.com/yichengchen/clashX/releases "
	green "======================================================================"
	green "?????? Android ?????????:"
	green "https://github.com/trojan-gfw/igniter/releases "
	green "https://github.com/Kr328/ClashForAndroid/releases "
	green "======================================================================"


    cat >> ${configReadme} <<-EOF

Trojan${promptInfoTrojanName} Version: ${configTrojanBaseVersion} ???????????? !
Trojan${promptInfoTrojanName} ???????????????????????? ${configTrojanBasePath}/server.json

Trojan${promptInfoTrojanName} ????????????????????????: ${configTrojanLogFile} 
Trojan${promptInfoTrojanName} ??????????????????: journalctl -n 50 -u trojan${promptInfoTrojanName}.service

Trojan${promptInfoTrojanName} ????????????: systemctl start trojan${promptInfoTrojanName}.service
Trojan${promptInfoTrojanName} ????????????: systemctl stop trojan${promptInfoTrojanName}.service  
Trojan${promptInfoTrojanName} ????????????: systemctl restart trojan${promptInfoTrojanName}.service
Trojan${promptInfoTrojanName} ????????????????????????: systemctl status trojan${promptInfoTrojanName}.service

Trojan${promptInfoTrojanName}???????????????: ${configSSLDomain}  ??????: $configV2rayTrojanPort

??????1: ${trojanPassword1}
??????2: ${trojanPassword2}
??????3: ${trojanPassword3}
??????4: ${trojanPassword4}
??????5: ${trojanPassword5}
??????6: ${trojanPassword6}
??????7: ${trojanPassword7}
??????8: ${trojanPassword8}
??????9: ${trojanPassword9}
??????10: ${trojanPassword10}
???????????????????????????20???: ??? ${configTrojanPasswordPrefixInput}202001 ??? ${configTrojanPasswordPrefixInput}202020 ???????????????
??????: ??????:${configTrojanPasswordPrefixInput}202002 ??? ??????:${configTrojanPasswordPrefixInput}202019 ???????????????

?????????trojan-go?????????Websocket?????????Websocket path ?????????: /${configTrojanGoWebSocketPath}

???????????????:
trojan://${trojanPassword1}@${configSSLDomain}:${configV2rayTrojanPort}?peer=${configSSLDomain}&sni=${configSSLDomain}#${configSSLDomain}_trojan"

????????? Trojan${promptInfoTrojanName}
https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3a%2f%2f${trojanPassword1}%40${configSSLDomain}%3a${configV2rayTrojanPort}%3fpeer%3d${configSSLDomain}%26sni%3d${configSSLDomain}%23${configSSLDomain}_trojan

EOF
}


function removeTrojan(){

    isTrojanGoInstall

    ${sudoCmd} systemctl stop trojan${promptInfoTrojanName}.service
    ${sudoCmd} systemctl disable trojan${promptInfoTrojanName}.service

    echo
    green " ================================================== "
    red " ????????????????????????trojan${promptInfoTrojanName}"
    green " ================================================== "
    echo

    rm -rf ${configTrojanBasePath}
    rm -f ${osSystemMdPath}trojan${promptInfoTrojanName}.service
    rm -f ${configTrojanLogFile}
    rm -f ${configTrojanGoLogFile}

    rm -f ${configReadme}

    crontab -r

    echo
    green " ================================================== "
    green "  trojan${promptInfoTrojanName} ??? nginx ???????????? !"
    green "  crontab ???????????? ???????????? !"
    green " ================================================== "
    echo
}


function upgradeTrojan(){

    isTrojanGoInstall

    green " ================================================== "
    green "     ???????????? Trojan${promptInfoTrojanName} Version: ${configTrojanBaseVersion}"
    green " ================================================== "

    ${sudoCmd} systemctl stop trojan${promptInfoTrojanName}.service

    mkdir -p ${configDownloadTempPath}/upgrade/trojan${promptInfoTrojanName}

    if [ "$isTrojanGo" = "no" ] ; then
        # https://github.com/trojan-gfw/trojan/releases/download/v1.16.0/trojan-1.16.0-linux-amd64.tar.xz
        downloadAndUnzip "https://github.com/trojan-gfw/trojan/releases/download/v${versionTrojan}/${downloadFilenameTrojan}" "${configDownloadTempPath}/upgrade/trojan" "${downloadFilenameTrojan}"
        mv -f ${configDownloadTempPath}/upgrade/trojan/trojan ${configTrojanPath}
    else
        # https://github.com/p4gefau1t/trojan-go/releases/download/v0.8.1/trojan-go-linux-amd64.zip
        downloadAndUnzip "https://github.com/p4gefau1t/trojan-go/releases/download/v${versionTrojanGo}/${downloadFilenameTrojanGo}" "${configDownloadTempPath}/upgrade/trojan-go" "${downloadFilenameTrojanGo}"
        mv -f ${configDownloadTempPath}/upgrade/trojan-go/trojan-go ${configTrojanGoPath}
    fi

    ${sudoCmd} systemctl start trojan${promptInfoTrojanName}.service

    green " ================================================== "
    green "     ???????????? Trojan${promptInfoTrojanName} Version: ${configTrojanBaseVersion} !"
    green " ================================================== "

}





























function inputV2rayWSPath(){ 
    configV2rayWebSocketPath="Aa112211"

    isV2rayUserWSPathInput="Aa112211"

    if [[ -z $isV2rayUserWSPathInput ]]; then
        echo
    else
        configV2rayWebSocketPath=${isV2rayUserWSPathInput}
    fi
}

function inputV2rayGRPCPath(){ 
    configV2rayGRPCServiceName=$(cat /dev/urandom | head -1 | md5sum | head -c 8)

    read -p "???????????????${promptInfoXrayName}??? gRPC ???serviceName ? ????????????????????????????????????, ????????????????????????(????????????/):" isV2rayUserGRPCPathInput
    isV2rayUserGRPCPathInput=${isV2rayUserGRPCPathInput:-${configV2rayGRPCServiceName}}

    if [[ -z $isV2rayUserGRPCPathInput ]]; then
        echo
    else
        configV2rayGRPCServiceName=${isV2rayUserGRPCPathInput}
    fi
}


function inputV2rayServerPort(){  
    echo
	if [[ $1 == "textMainPort" ]]; then

        isV2rayUserPortInput=${configV2rayPortShowInfo}
		checkPortInUse "${isV2rayUserPortInput}" $1 
	fi

	if [[ $1 == "textMainGRPCPort" ]]; then
        green " ????????????gRPC ??????????????????cloudflare???CDN, ?????????????????? 443 ???????????????"
        read -p "???????????????${promptInfoXrayName} gRPC????????????? ?????????????????????${configV2rayPortGRPCShowInfo}, ???????????????????????????[1-65535]:" isV2rayUserPortGRPCInput
        isV2rayUserPortGRPCInput=${isV2rayUserPortGRPCInput:-${configV2rayPortGRPCShowInfo}}
		checkPortInUse "${isV2rayUserPortGRPCInput}" $1 
	fi    

	if [[ $1 == "textAdditionalPort" ]]; then
        green " ????????????????????????????????????, ????????????${configV2rayPort}??????????????????"
        green " ???????????? ?????????????????????443????????????????????????????????????"
        read -p "?????????${promptInfoXrayName}???????????????????????????? ?????????????????????, ????????????????????????[1-65535]:" isV2rayAdditionalPortInput
        isV2rayAdditionalPortInput=${isV2rayAdditionalPortInput:-999999}
        checkPortInUse "${isV2rayAdditionalPortInput}" $1 
	fi


    if [[ $1 == "textMainTrojanPort" ]]; then
        isTrojanUserPortInput=443
		checkPortInUse "${isTrojanUserPortInput}" $1 
	fi    
}

function checkPortInUse(){ 
    if [ $1 = "999999" ]; then
        echo
    elif [[ $1 -gt 1 && $1 -le 65535 ]]; then
            
        netstat -tulpn | grep [0-9]:$1 -q ; 
        if [ $? -eq 1 ]; then 
            green "?????????????????? $1 ???????????????, ????????????..."  
            
        else 
            red "?????????????????? $1 ????????????! ???????????????, ?????????????????????????????? ??? ????????????!" 
            inputV2rayServerPort $2 
        fi
    else
        red "????????????????????????! ?????????[1-65535]. ???????????????" 
        inputV2rayServerPort $2 
    fi
}




function installV2ray(){

    v2rayPassword1="119a6b79-8308-5416-9eca-9f93225b52d1"
    v2rayPassword2=$(cat /proc/sys/kernel/random/uuid)
    v2rayPassword3=$(cat /proc/sys/kernel/random/uuid)
    v2rayPassword4=$(cat /proc/sys/kernel/random/uuid)
    v2rayPassword5=$(cat /proc/sys/kernel/random/uuid)
    v2rayPassword6=$(cat /proc/sys/kernel/random/uuid)
    v2rayPassword7=$(cat /proc/sys/kernel/random/uuid)
    v2rayPassword8=$(cat /proc/sys/kernel/random/uuid)
    v2rayPassword9=$(cat /proc/sys/kernel/random/uuid)
    v2rayPassword10=$(cat /proc/sys/kernel/random/uuid)

    echo
    if [ -f "${configV2rayPath}/xray" ] || [ -f "${configV2rayPath}/v2ray" ] || [ -f "/usr/local/bin/v2ray" ] || [ -f "/usr/bin/v2ray" ]; then
        green " =================================================="
        green "     ???????????? V2ray ??? Xray, ???????????? !"
        green " =================================================="
        exit
    fi

    green " =================================================="
    green "    ???????????? V2ray or Xray "
    green " =================================================="    
    echo


    if [[ ( $configV2rayVlessMode == "trojan" ) || ( $configV2rayVlessMode == "vlessxtlsws" ) || ( $configV2rayVlessMode == "vlessxtlstrojan" ) ]] ; then
        promptInfoXrayName="xray"
        isXray="yes"
    else
        isV2rayOrXrayInput="y"

        if [[ $isV2rayOrXrayInput == [Yy] ]]; then
            promptInfoXrayName="xray"
            isXray="yes"
        fi
    fi


    if [[ -n "$configV2rayVlessMode" ]]; then
         configV2rayProtocol="vless"
    else 

        echo
        isV2rayUseVLessInput="y"

        if [[ $isV2rayUseVLessInput == [Yy] ]]; then
            configV2rayProtocol="vless"
        else
            configV2rayProtocol="vmess"
        fi

    fi

    isV2rayUnlockGoogleInput="1"

    V2rayUnlockText=""

    echo
    isV2rayUserPassordInput=""

    if [[ -z $isV2rayUserPassordInput ]]; then
        isV2rayUserPassordInput=""
    else
        v2rayPassword1=${isV2rayUserPassordInput}
    fi



    # ????????????????????????
    if [[ ${isInstallNginx} == "true" ]]; then
        configV2rayPortShowInfo=443
        configV2rayPortGRPCShowInfo=443
        
        if [[ $configV2rayVlessMode == "vlessxtlstrojan" ]]; then
            configV2rayPort=443
        fi
    else
        configV2rayPort="$(($RANDOM + 10000))"
        
        if [[ -n "$configV2rayVlessMode" ]]; then
            configV2rayPort=443
        fi
        configV2rayPortShowInfo=$configV2rayPort

        inputV2rayServerPort "textMainPort"

        configV2rayPort=${isV2rayUserPortInput}   
        configV2rayPortShowInfo=${isV2rayUserPortInput}   


        if [[ ( $configV2rayWSorGrpc == "grpc" ) || ( $configV2rayVlessMode == "wsgrpc" ) ]]; then
            inputV2rayServerPort "textMainGRPCPort"

            configV2rayGRPCPort=${isV2rayUserPortGRPCInput}   
            configV2rayPortGRPCShowInfo=${isV2rayUserPortGRPCInput}   
        fi


        echo
        if [[ ( $configV2rayWSorGrpc == "grpc" ) || ( $configV2rayVlessMode == "wsgrpc" ) || ( $configV2rayVlessMode == "vlessgrpc" ) ]]; then
            inputV2rayGRPCPath
        else
            inputV2rayWSPath
        fi




        
        
        inputV2rayServerPort "textAdditionalPort"

        if [[ $isV2rayAdditionalPortInput == "999999" ]]; then
            v2rayConfigAdditionalPortInput=""
        else
            read -r -d '' v2rayConfigAdditionalPortInput << EOM
        ,
        {
            "listen": "0.0.0.0",
            "port": ${isV2rayAdditionalPortInput}, 
            "protocol": "dokodemo-door",
            "settings": {
                "address": "127.0.0.1",
                "port": ${configV2rayPort},
                "network": "tcp, udp",
                "followRedirect": false 
            },
            "sniffing": {
            "enabled": true,
            "destOverride": ["http", "tls"]
            }
        }     

EOM

        fi

    fi




    
    if [ "$isXray" = "no" ] ; then
        getTrojanAndV2rayVersion "v2ray"
        green "    ????????????????????? V2ray Version: ${versionV2ray} !"
        promptInfoXrayInstall="V2ray"
        promptInfoXrayVersion=${versionV2ray}
    else
        getTrojanAndV2rayVersion "xray"
        green "    ????????????????????? Xray Version: ${versionXray} !"
        promptInfoXrayInstall="Xray"
        promptInfoXrayVersion=${versionXray}
    fi
    echo


    mkdir -p ${configV2rayPath}
    cd ${configV2rayPath}
    rm -rf ${configV2rayPath}/*


    if [ "$isXray" = "no" ] ; then
        # https://github.com/v2fly/v2ray-core/releases/download/v4.27.5/v2ray-linux-64.zip
        downloadAndUnzip "https://github.com/v2fly/v2ray-core/releases/download/v${versionV2ray}/${downloadFilenameV2ray}" "${configV2rayPath}" "${downloadFilenameV2ray}"

    else
        downloadAndUnzip "https://github.com/XTLS/Xray-core/releases/download/v${versionXray}/${downloadFilenameXray}" "${configV2rayPath}" "${downloadFilenameXray}"
    fi

    # ?????? v2ray ??????????????????
    configV2rayWebSocketPath="Aa112211"
    trojanPassword1="Aa112211"
    trojanPassword2=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword3=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword4=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword5=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword6=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword7=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword8=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword9=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword10=$(cat /dev/urandom | head -1 | md5sum | head -c 10)

    read -r -d '' v2rayConfigUserpasswordTrojanInput << EOM
                    {
                        "password": "${trojanPassword1}",
                        "level": 0,
                        "email": "password111@gmail.com"
                    },
                    {
                        "password": "${trojanPassword2}",
                        "level": 0,
                        "email": "password112@gmail.com"
                    },
                    {
                        "password": "${trojanPassword3}",
                        "level": 0,
                        "email": "password113@gmail.com"
                    },
                    {
                        "password": "${trojanPassword4}",
                        "level": 0,
                        "email": "password114@gmail.com"
                    },
                    {
                        "password": "${trojanPassword5}",
                        "level": 0,
                        "email": "password115@gmail.com"
                    },
                    {
                        "password": "${trojanPassword6}",
                        "level": 0,
                        "email": "password116@gmail.com"
                    },
                    {
                        "password": "${trojanPassword7}",
                        "level": 0,
                        "email": "password117@gmail.com"
                    },
                    {
                        "password": "${trojanPassword8}",
                        "level": 0,
                        "email": "password118@gmail.com"
                    },
                    {
                        "password": "${trojanPassword9}",
                        "level": 0,
                        "email": "password119@gmail.com"
                    },
                    {
                        "password": "${trojanPassword10}",
                        "level": 0,
                        "email": "password120@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202001",
                        "level": 0,
                        "email": "password201@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202002",
                        "level": 0,
                        "email": "password202@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202003",
                        "level": 0,
                        "email": "password203@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202004",
                        "level": 0,
                        "email": "password204@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202005",
                        "level": 0,
                        "email": "password205@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202006",
                        "level": 0,
                        "email": "password206@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202007",
                        "level": 0,
                        "email": "password207@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202008",
                        "level": 0,
                        "email": "password208@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202009",
                        "level": 0,
                        "email": "password209@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202010",
                        "level": 0,
                        "email": "password210@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202011",
                        "level": 0,
                        "email": "password211@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202012",
                        "level": 0,
                        "email": "password212@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202013",
                        "level": 0,
                        "email": "password213@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202014",
                        "level": 0,
                        "email": "password214@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202015",
                        "level": 0,
                        "email": "password215@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202016",
                        "level": 0,
                        "email": "password216@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202017",
                        "level": 0,
                        "email": "password217@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202018",
                        "level": 0,
                        "email": "password218@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202019",
                        "level": 0,
                        "email": "password219@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202020",
                        "level": 0,
                        "email": "password220@gmail.com"
                    }
EOM


    read -r -d '' v2rayConfigUserpasswordInput << EOM
                    {
                        "id": "${v2rayPassword1}",
                        "level": 0,
                        "email": "password11@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword2}",
                        "level": 0,
                        "email": "password12@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword3}",
                        "level": 0,
                        "email": "password13@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword4}",
                        "level": 0,
                        "email": "password14@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword5}",
                        "level": 0,
                        "email": "password15@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword6}",
                        "level": 0,
                        "email": "password16@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword7}",
                        "level": 0,
                        "email": "password17@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword8}",
                        "level": 0,
                        "email": "password18@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword9}",
                        "level": 0,
                        "email": "password19@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword10}",
                        "level": 0,
                        "email": "password20@gmail.com"
                    }
EOM

    read -r -d '' v2rayConfigUserpasswordDirectInput << EOM
                    {
                        "id": "${v2rayPassword1}",
                        "flow": "xtls-rprx-direct",
                        "level": 0,
                        "email": "password11@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword2}",
                        "flow": "xtls-rprx-direct",
                        "level": 0,
                        "email": "password12@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword3}",
                        "flow": "xtls-rprx-direct",
                        "level": 0,
                        "email": "password13@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword4}",
                        "flow": "xtls-rprx-direct",
                        "level": 0,
                        "email": "password14@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword5}",
                        "flow": "xtls-rprx-direct",
                        "level": 0,
                        "email": "password15@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword6}",
                        "flow": "xtls-rprx-direct",
                        "level": 0,
                        "email": "password16@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword7}",
                        "flow": "xtls-rprx-direct",
                        "level": 0,
                        "email": "password17@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword8}",
                        "flow": "xtls-rprx-direct",
                        "level": 0,
                        "email": "password18@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword9}",
                        "flow": "xtls-rprx-direct",
                        "level": 0,
                        "email": "password19@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword10}",
                        "flow": "xtls-rprx-direct",
                        "level": 0,
                        "email": "password20@gmail.com"
                    }
EOM


    if [[ $isV2rayUnlockGoogleInput == "1" ]]; then

        read -r -d '' v2rayConfigOutboundInput << EOM
    "outbounds": [
        {
            "tag": "direct",
            "protocol": "freedom",
            "settings": {}
        },
        {
            "tag": "blocked",
            "protocol": "blackhole",
            "settings": {}
        }
    ]
EOM

    else

        read -r -d '' v2rayConfigOutboundInput << EOM
    "outbounds": [
        {
            "tag":"IP4_out",
            "protocol": "freedom",
            "settings": {}
        },
        {
            "tag":"IP6_out",
            "protocol": "freedom",
            "settings": {
                "domainStrategy": "UseIPv6" 
            }
        }
    ],    
    "routing": {
        "rules": [
            {
                "type": "field",
                "outboundTag": "IP6_out",
                "domain": [${V2rayUnlockText}] 
            },
            {
                "type": "field",
                "outboundTag": "IP4_out",
                "network": "udp,tcp"
            }
        ]
    }
EOM
        
    fi




    read -r -d '' v2rayConfigLogInput << EOM
    "log" : {
        "access": "${configV2rayAccessLogFilePath}",
        "error": "${configV2rayErrorLogFilePath}",
        "loglevel": "warning"
    },
EOM




    if [[ -z "$configV2rayVlessMode" ]]; then

        if [[ "$configV2rayWSorGrpc" == "grpc" ]]; then
            cat > ${configV2rayPath}/config.json <<-EOF
{
    ${v2rayConfigLogInput}
    "inbounds": [
        {
            "port": ${configV2rayGRPCPort},
            "protocol": "${configV2rayProtocol}",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordInput}
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {
                    "serviceName": "${configV2rayGRPCServiceName}" 
                }
            }
        }
        ${v2rayConfigAdditionalPortInput}
    ],
    ${v2rayConfigOutboundInput}
}
EOF
        elif [[ "$configV2rayWSorGrpc" == "wsgrpc" ]]; then
            cat > ${configV2rayPath}/config.json <<-EOF
{
    ${v2rayConfigLogInput}
    "inbounds": [
        {
            "port": ${configV2rayPort},
            "protocol": "${configV2rayProtocol}",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordInput}
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/${configV2rayWebSocketPath}"
                }
            }
        },
        {
            "port": ${configV2rayGRPCPort},
            "protocol": "${configV2rayProtocol}",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordInput}
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {
                    "serviceName": "${configV2rayGRPCServiceName}" 
                }
            }
        }
        ${v2rayConfigAdditionalPortInput}
    ],
    ${v2rayConfigOutboundInput}
}
EOF

        else
            cat > ${configV2rayPath}/config.json <<-EOF
{
    ${v2rayConfigLogInput}
    "inbounds": [
        {
            "port": ${configV2rayPort},
            "protocol": "${configV2rayProtocol}",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordInput}
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/${configV2rayWebSocketPath}"
                }
            }
        }
        ${v2rayConfigAdditionalPortInput}
    ],
    ${v2rayConfigOutboundInput}
}
EOF

        fi

    fi


    if [[ "$configV2rayVlessMode" == "vlessws" ]]; then
        cat > ${configV2rayPath}/config.json <<-EOF
{
    ${v2rayConfigLogInput}
    "inbounds": [
        {
            "port": ${configV2rayPort},
            "protocol": "${configV2rayProtocol}",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordInput}
                ],
                "decryption": "none",
                "fallbacks": [
                    {
                        "dest": 80
                    },
                    {
                        "path": "/${configV2rayWebSocketPath}",
                        "dest": ${configV2rayVmesWSPort},
                        "xver": 1
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "alpn": [
                        "http/1.1"
                    ],
                    "certificates": [
                        {
                            "certificateFile": "${configSSLCertPath}/$configSSLCertFullchainFilename",
                            "keyFile": "${configSSLCertPath}/$configSSLCertKeyFilename"
                        }
                    ]
                }
            }
        },
        {
            "port": ${configV2rayVmesWSPort},
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordInput}
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "acceptProxyProtocol": true,
                    "path": "/${configV2rayWebSocketPath}" 
                }
            }
        }
        ${v2rayConfigAdditionalPortInput}
    ],
    ${v2rayConfigOutboundInput}
}
EOF
    fi


    if [[ "$configV2rayVlessMode" == "vlessgrpc" ]]; then
        cat > ${configV2rayPath}/config.json <<-EOF
{
    ${v2rayConfigLogInput}
    "inbounds": [
        {
            "port": ${configV2rayPort},
            "protocol": "${configV2rayProtocol}",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordInput}
                ],
                "decryption": "none",
                "fallbacks": [
                    {
                        "dest": 80
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "security": "tls",
                "tlsSettings": {
                    "alpn": [
                        "h2", 
                        "http/1.1"
                    ],
                    "certificates": [
                        {
                            "certificateFile": "${configSSLCertPath}/$configSSLCertFullchainFilename",
                            "keyFile": "${configSSLCertPath}/$configSSLCertKeyFilename"
                        }
                    ]
                },
                "grpcSettings": {
                    "serviceName": "${configV2rayGRPCServiceName}"
                }
            }
        }
        ${v2rayConfigAdditionalPortInput}
    ],
    ${v2rayConfigOutboundInput}
}
EOF
    fi



    if [[ "$configV2rayVlessMode" == "vmessws" ]]; then
        cat > ${configV2rayPath}/config.json <<-EOF
{
    ${v2rayConfigLogInput}
    "inbounds": [
        {
            "port": ${configV2rayPort},
            "protocol": "${configV2rayProtocol}",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordInput}
                ],
                "decryption": "none",
                "fallbacks": [
                    {
                        "dest": 80
                    },
                    {
                        "path": "/${configV2rayWebSocketPath}",
                        "dest": ${configV2rayVmesWSPort},
                        "xver": 1
                    },
                    {
                        "path": "/tcp${configV2rayWebSocketPath}",
                        "dest": ${configV2rayVmessTCPPort},
                        "xver": 1
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "alpn": [
                        "http/1.1"
                    ],
                    "certificates": [
                        {
                            "certificateFile": "${configSSLCertPath}/$configSSLCertFullchainFilename",
                            "keyFile": "${configSSLCertPath}/$configSSLCertKeyFilename"
                        }
                    ]
                }
            }
        },
        {
            "port": ${configV2rayVmesWSPort},
            "listen": "127.0.0.1",
            "protocol": "vmess",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordInput}
                ]
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "path": "/${configV2rayWebSocketPath}" 
                }
            }
        },
        {
            "port": ${configV2rayVmessTCPPort},
            "listen": "127.0.0.1",
            "protocol": "vmess",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordInput}
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none",
                "tcpSettings": {
                    "acceptProxyProtocol": true,
                    "header": {
                        "type": "http",
                        "request": {
                            "path": [
                                "/tcp${configV2rayWebSocketPath}"
                            ]
                        }
                    }
                }
            }
        }
        ${v2rayConfigAdditionalPortInput}
    ],
    ${v2rayConfigOutboundInput}
}
EOF
    fi



    if [[  $configV2rayVlessMode == "vlessxtlstrojan" ]]; then
            cat > ${configV2rayPath}/config.json <<-EOF
{
    ${v2rayConfigLogInput}
    "inbounds": [
        {
            "port": ${configV2rayPort},
            "protocol": "${configV2rayProtocol}",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordDirectInput}
                ],
                "decryption": "none",
                "fallbacks": [
                    {
                        "dest": ${configV2rayTrojanPort},
                        "xver": 1
                    },
                    {
                        "path": "/${configV2rayWebSocketPath}",
                        "dest": ${configV2rayVmesWSPort},
                        "xver": 1
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "xtls",
                "xtlsSettings": {
                    "alpn": [
                        "http/1.1"
                    ],
                    "certificates": [
                        {
                            "certificateFile": "${configSSLCertPath}/$configSSLCertFullchainFilename",
                            "keyFile": "${configSSLCertPath}/$configSSLCertKeyFilename"
                        }
                    ]
                }
            }
        },
        {
            "port": ${configV2rayTrojanPort},
            "listen": "127.0.0.1",
            "protocol": "trojan",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordTrojanInput}
                ],
                "fallbacks": [
                    {
                        "dest": 80 
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none",
                "tcpSettings": {
                    "acceptProxyProtocol": true
                }
            }
        },
        {
            "port": ${configV2rayVmesWSPort},
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordInput}
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "acceptProxyProtocol": true,
                    "path": "/${configV2rayWebSocketPath}" 
                }
            }
        }
        ${v2rayConfigAdditionalPortInput}
    ],
    ${v2rayConfigOutboundInput}
}
EOF
    fi


    if [[  $configV2rayVlessMode == "vlessxtlsws" ]]; then
            cat > ${configV2rayPath}/config.json <<-EOF
{
    ${v2rayConfigLogInput}
    "inbounds": [
        {
            "port": ${configV2rayPort},
            "protocol": "${configV2rayProtocol}",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordDirectInput}
                ],
                "decryption": "none",
                "fallbacks": [
                    {
                        "dest": 80
                    },
                    {
                        "path": "/${configV2rayWebSocketPath}",
                        "dest": ${configV2rayVmesWSPort},
                        "xver": 1
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "xtls",
                "xtlsSettings": {
                    "alpn": [
                        "http/1.1"
                    ],
                    "certificates": [
                        {
                            "certificateFile": "${configSSLCertPath}/$configSSLCertFullchainFilename",
                            "keyFile": "${configSSLCertPath}/$configSSLCertKeyFilename"
                        }
                    ]
                }
            }
        },
        {
            "port": ${configV2rayVmesWSPort},
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordInput}
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "acceptProxyProtocol": true,
                    "path": "/${configV2rayWebSocketPath}" 
                }
            }
        }
        ${v2rayConfigAdditionalPortInput}
    ],
    ${v2rayConfigOutboundInput}
}
EOF
    fi






    if [[ $configV2rayVlessMode == "trojan" ]]; then

            cat > ${configV2rayPath}/config.json <<-EOF
{
    ${v2rayConfigLogInput}
    "inbounds": [
        {
            "port": ${configV2rayPort},
            "protocol": "${configV2rayProtocol}",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordDirectInput}
                ],
                "decryption": "none",
                "fallbacks": [
                    {
                        "dest": ${configV2rayTrojanPort},
                        "xver": 1
                    },
                    {
                        "path": "/${configTrojanGoWebSocketPath}",
                        "dest": ${configV2rayTrojanPort},
                        "xver": 1
                    },
                    {
                        "path": "/${configV2rayWebSocketPath}",
                        "dest": ${configV2rayVmesWSPort},
                        "xver": 1
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "xtls",
                "xtlsSettings": {
                    "alpn": [
                        "http/1.1"
                    ],
                    "certificates": [
                        {
                            "certificateFile": "${configSSLCertPath}/$configSSLCertFullchainFilename",
                            "keyFile": "${configSSLCertPath}/$configSSLCertKeyFilename"
                        }
                    ]
                }
            }
        },
        {
            "port": ${configV2rayVmesWSPort},
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordInput}
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "acceptProxyProtocol": true,
                    "path": "/${configV2rayWebSocketPath}" 
                }
            }
        }
        ${v2rayConfigAdditionalPortInput}
    ],
    ${v2rayConfigOutboundInput}
}
EOF

    fi



    # ?????? V2ray????????????
    if [ "$isXray" = "no" ] ; then
    
        cat > ${osSystemMdPath}v2ray.service <<-EOF
[Unit]
Description=V2Ray
Documentation=https://www.v2fly.org/
After=network.target nss-lookup.target

[Service]
Type=simple
# This service runs as root. You may consider to run it as another user for security concerns.
# By uncommenting User=nobody and commenting out User=root, the service will run as user nobody.
# More discussion at https://github.com/v2ray/v2ray-core/issues/1011
User=root
#User=nobody
#CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=${configV2rayPath}/v2ray -config ${configV2rayPath}/config.json
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF
    else
        cat > ${osSystemMdPath}xray.service <<-EOF
[Unit]
Description=Xray
Documentation=https://www.v2fly.org/
After=network.target nss-lookup.target

[Service]
Type=simple
# This service runs as root. You may consider to run it as another user for security concerns.
# By uncommenting User=nobody and commenting out User=root, the service will run as user nobody.
# More discussion at https://github.com/v2ray/v2ray-core/issues/1011
User=root
#User=nobody
#CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=${configV2rayPath}/xray run -config ${configV2rayPath}/config.json
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF
    fi

    ${sudoCmd} chmod +x ${configV2rayPath}/${promptInfoXrayName}
    ${sudoCmd} chmod +x ${osSystemMdPath}${promptInfoXrayName}.service
    ${sudoCmd} systemctl daemon-reload
    
    ${sudoCmd} systemctl enable ${promptInfoXrayName}.service
    ${sudoCmd} systemctl restart ${promptInfoXrayName}.service



    # ???????????????????????????
    if [[ ${isInstallNginx} != "true" ]]; then
        if [[ -z "$configV2rayVlessMode" ]]; then
                        
            configV2rayIsTlsShowInfo="none"
        fi
    fi


    # https://stackoverflow.com/questions/296536/how-to-urlencode-data-for-curl-command

    rawurlencode() {
        local string="${1}"
        local strlen=${#string}
        local encoded=""
        local pos c o

        for (( pos=0 ; pos<strlen ; pos++ )); do
            c=${string:$pos:1}
            case "$c" in
                [-_.~a-zA-Z0-9] ) o="${c}" ;;
                * )               printf -v o '%%%02x' "'$c"
            esac
            encoded+="${o}"
        done
        echo
        green "URL Encoded: ${encoded}"    # You can either set a return variable (FASTER) 
        v2rayPassUrl="${encoded}"   #+or echo the result (EASIER)... or both... :p
    }

    rawurlencode "${v2rayPassword1}"

    base64VmessLink=$(echo -n '{"port":"'${configV2rayPortShowInfo}'","ps":'${configSSLDomain}',"tls":"tls","id":'"${v2rayPassword1}"',"aid":"1","v":"2","host":"'${configSSLDomain}'","type":"none","path":"/'${configV2rayWebSocketPath}'","net":"ws","add":"'${configSSLDomain}'","allowInsecure":0,"method":"none","peer":"'${configSSLDomain}'"}' | sed 's#/#\\\/#g' | base64)
    base64VmessLink2=$(echo ${base64VmessLink} | sed 's/ //g')






    if [[ "$configV2rayWSorGrpc" == "grpc" ]]; then
        cat > ${configV2rayPath}/clientConfig.json <<-EOF
=========== ${promptInfoXrayInstall}????????????????????? =============
{
    ??????: ${configV2rayProtocol},
    ??????: ${configSSLDomain},
    ??????: ${configV2rayPortGRPCShowInfo},
    uuid: ${v2rayPassword1},
    ??????id: 0,  // AlterID ?????????Vless????????????????????????
    ????????????: aes-128-gcm,  // ?????????Vless????????????none
    ????????????: gRPC,
    gRPC serviceName: ${configV2rayGRPCServiceName},
    ??????????????????:${configV2rayIsTlsShowInfo},
    ??????:????????????????????????
}

???????????? Vless (grpc???????????????????????????, ?????????????????????????????????):
${configV2rayProtocol}://${v2rayPassUrl}@${configSSLDomain}:${configV2rayPortGRPCShowInfo}?encryption=none&security=${configV2rayIsTlsShowInfo}&type=grpc&serviceName=${configV2rayGRPCServiceName}&host=${configSSLDomain}&headerType=none#${configSSLDomain}+gRPC%E5%8D%8F%E8%AE%AE

EOF

    elif [[ "$configV2rayWSorGrpc" == "wsgrpc" ]]; then
        cat > ${configV2rayPath}/clientConfig.json <<-EOF
=========== ${promptInfoXrayInstall} ????????????????????? =============
{
    ??????: ${configV2rayProtocol},
    ??????: ${configSSLDomain},
    ??????: ${configV2rayPortShowInfo},
    uuid: ${v2rayPassword1},
    ??????id: 0,  // AlterID ?????????Vless????????????????????????
    ????????????: aes-128-gcm,  // ?????????Vless????????????none
    ????????????: websocket,
    websocket??????:/${configV2rayWebSocketPath},
    ??????????????????:${configV2rayIsTlsShowInfo},
    ??????:????????????????????????
}

???????????? Vless:
${configV2rayProtocol}://${v2rayPassUrl}@${configSSLDomain}:${configV2rayPortShowInfo}?encryption=none&security=${configV2rayIsTlsShowInfo}&type=ws&path=%2f${configV2rayWebSocketPath}&host=${configSSLDomain}&headerType=none#${configSSLDomain}+ws%E5%8D%8F%E8%AE%AE

???????????? Vmess:
vmess://${base64VmessLink2}


=========== ${promptInfoXrayInstall} gRPC ????????????????????? =============
{
    ??????: ${configV2rayProtocol},
    ??????: ${configSSLDomain},
    ??????: ${configV2rayPortGRPCShowInfo},
    uuid: ${v2rayPassword1},
    ??????id: 0,  // AlterID ?????????Vless????????????????????????
    ????????????: aes-128-gcm,  // ?????????Vless????????????none
    ????????????: gRPC,
    gRPC serviceName: ${configV2rayGRPCServiceName},
    ??????????????????:${configV2rayIsTlsShowInfo},
    ??????:????????????????????????
}

???????????? Vless (grpc???????????????????????????, ?????????????????????????????????):
${configV2rayProtocol}://${v2rayPassUrl}@${configSSLDomain}:${configV2rayPortGRPCShowInfo}?encryption=none&security=${configV2rayIsTlsShowInfo}&type=grpc&serviceName=${configV2rayGRPCServiceName}&host=${configSSLDomain}&headerType=none#${configSSLDomain}+gRPC%E5%8D%8F%E8%AE%AE

EOF

    else
        cat > ${configV2rayPath}/clientConfig.json <<-EOF
=========== ${promptInfoXrayInstall}????????????????????? =============
{
    ??????: ${configV2rayProtocol},
    ??????: ${configSSLDomain},
    ??????: ${configV2rayPortShowInfo},
    uuid: ${v2rayPassword1},
    ??????id: 0,  // AlterID ?????????Vless????????????????????????
    ????????????: aes-128-gcm,  // ?????????Vless????????????none
    ????????????: websocket,
    websocket??????:/${configV2rayWebSocketPath},
    ??????????????????:${configV2rayIsTlsShowInfo},
    ??????:????????????????????????
}

???????????? Vless:
${configV2rayProtocol}://${v2rayPassUrl}@${configSSLDomain}:${configV2rayPortShowInfo}?encryption=none&security=${configV2rayIsTlsShowInfo}&type=ws&path=%2f${configV2rayWebSocketPath}&host=${configSSLDomain}&headerType=none#${configSSLDomain}+ws%E5%8D%8F%E8%AE%AE

???????????? Vmess:
vmess://${base64VmessLink2}

EOF

    fi





    if [[ "$configV2rayVlessMode" == "vmessws" ]]; then

        base64VmessLink=$(echo -n '{"port":"'${configV2rayPort}'","ps":'${configSSLDomain}',"tls":"tls","id":'"${v2rayPassword1}"',"aid":"1","v":"2","host":"'${configSSLDomain}'","type":"none","path":"/'${configV2rayWebSocketPath}'","net":"ws","add":"'${configSSLDomain}'","allowInsecure":0,"method":"none","peer":"'${configSSLDomain}'"}' | sed 's#/#\\\/#g' | base64)
        base64VmessLink2=$(echo ${base64VmessLink} | sed 's/ //g')

        base64VmessLinkTCP=$(echo -n '{"port":"'${configV2rayPort}'","ps":'${configSSLDomain}',"tls":"tls","id":'"${v2rayPassword1}"',"aid":"1","v":"2","host":"'${configSSLDomain}'","type":"none","path":"/tcp'${configV2rayWebSocketPath}'","net":"tcp","add":"'${configSSLDomain}'","allowInsecure":0,"method":"none","peer":"'${configSSLDomain}'"}' | sed 's#/#\\\/#g' | base64)
        base64VmessLinkTCP2=$(echo ${base64VmessLinkTCP} | sed 's/ //g')


        cat > ${configV2rayPath}/clientConfig.json <<-EOF

?????????v2ray VLess?????????443?????? (VLess-TCP-TLS) + (VMess-TCP-TLS) + (VMess-WS-TLS)  ??????CDN, ?????????nginx

=========== ${promptInfoXrayInstall}????????? VLess-TCP-TLS ???????????? =============
{
    ??????: VLess,
    ??????: ${configSSLDomain},
    ??????: ${configV2rayPort},
    uuid: ${v2rayPassword1},
    ??????id: 0,  // AlterID ?????????Vless????????????????????????
    ????????????: none,  // ?????????Vless????????????none
    ????????????: tcp ,
    websocket??????:???,
    ????????????:tls,
    ??????:????????????????????????
}

????????????:
vless://${v2rayPassUrl}@${configSSLDomain}:${configV2rayPort}?encryption=none&security=tls&type=tcp&host=${configSSLDomain}&headerType=none#${configSSLDomain}


=========== ${promptInfoXrayInstall}????????? VMess-WS-TLS ???????????? ??????CDN =============
{
    ??????: VMess,
    ??????: ${configSSLDomain},
    ??????: ${configV2rayPort},
    uuid: ${v2rayPassword1},
    ??????id: 0,  // AlterID ?????????Vless????????????????????????
    ????????????: auto,  // ?????????Vless????????????none
    ????????????: websocket,
    websocket??????:/${configV2rayWebSocketPath},
    ????????????:tls,
    ??????:????????????????????????
}

???????????? Vmess:
vmess://${base64VmessLink2}

??????????????????:
vmess://${v2rayPassUrl}@${configSSLDomain}:${configV2rayPort}?encryption=auto&security=tls&type=ws&host=${configSSLDomain}&path=%2f${configV2rayWebSocketPath}#${configSSLDomain}+ws%E5%8D%8F%E8%AE%AE



=========== ${promptInfoXrayInstall}????????? VMess-TCP-TLS ???????????? ??????CDN =============
{
    ??????: VMess,
    ??????: ${configSSLDomain},
    ??????: ${configV2rayPort},
    uuid: ${v2rayPassword1},
    ??????id: 0,  // AlterID ?????????Vless????????????????????????
    ????????????: auto,  // ?????????Vless????????????none
    ????????????: tcp,
    ??????:/tcp${configV2rayWebSocketPath},
    ????????????:tls,
    ??????:????????????????????????
}

???????????? Vmess:
vmess://${base64VmessLinkTCP2}

??????????????????:
vmess://${v2rayPassUrl}@${configSSLDomain}:${configV2rayPort}?encryption=auto&security=tls&type=tcp&host=${configSSLDomain}&path=%2ftcp${configV2rayWebSocketPath}#${configSSLDomain}


EOF
    fi



    if [[ "$configV2rayVlessMode" == "vlessws" ]]; then

    cat > ${configV2rayPath}/clientConfig.json <<-EOF
?????????v2ray VLess?????????443?????? (VLess-TCP-TLS) + (VLess-WS-TLS) ??????CDN, ?????????nginx

=========== ${promptInfoXrayInstall}????????? VLess-TCP-TLS ???????????? =============
{
    ??????: VLess,
    ??????: ${configSSLDomain},
    ??????: ${configV2rayPort},
    uuid: ${v2rayPassword1},
    ??????id: 0,  // AlterID ?????????Vless????????????????????????
    ??????flow: ???
    ????????????: none, 
    ????????????: tcp ,
    websocket??????:???,
    ??????????????????:tls,   
    ??????:????????????????????????
}

????????????:
vless://${v2rayPassUrl}@${configSSLDomain}:${configV2rayPort}?encryption=none&security=tls&type=tcp&host=${configSSLDomain}&headerType=none#${configSSLDomain}


=========== ${promptInfoXrayInstall}????????? VLess-WS-TLS ???????????? ??????CDN =============
{
    ??????: VLess,
    ??????: ${configSSLDomain},
    ??????: ${configV2rayPort},
    uuid: ${v2rayPassword1},
    ??????id: 0,  // AlterID ?????????Vless????????????????????????
    ??????flow: ???,
    ????????????: none,  
    ????????????: websocket,
    websocket??????:/${configV2rayWebSocketPath},
    ????????????:tls,     
    ??????:????????????????????????
}

????????????:
vless://${v2rayPassUrl}@${configSSLDomain}:${configV2rayPort}?encryption=none&security=tls&type=ws&host=${configSSLDomain}&path=%2f${configV2rayWebSocketPath}#${configSSLDomain}+ws%E5%8D%8F%E8%AE%AE

EOF
    fi



    if [[ "$configV2rayVlessMode" == "vlessgrpc" ]]; then

    cat > ${configV2rayPath}/clientConfig.json <<-EOF
?????????v2ray VLess?????????443?????? (VLess-gRPC-TLS) ??????CDN, ?????????nginx

=========== ${promptInfoXrayInstall}????????? VLess-gRPC-TLS ???????????? ??????CDN =============
{
    ??????: VLess,
    ??????: ${configSSLDomain},
    ??????: ${configV2rayPort},
    uuid: ${v2rayPassword1},
    ??????id: 0,  // AlterID ?????????Vless????????????????????????
    ??????flow:  ???,
    ????????????: none,  
    ????????????: gRPC,
    gRPC serviceName: ${configV2rayGRPCServiceName},
    ????????????:tls,     
    ??????:????????????????????????
}


???????????? Vless (grpc???????????????????????????, ?????????????????????????????????):
vless://${v2rayPassUrl}@${configSSLDomain}:${configV2rayPort}?encryption=none&security=tls&type=grpc&serviceName=${configV2rayGRPCServiceName}&host=${configSSLDomain}#${configSSLDomain}+gRPC%E5%8D%8F%E8%AE%AE


EOF
    fi




    if [[ "$configV2rayVlessMode" == "vlessxtlsws" ]] || [[ "$configV2rayVlessMode" == "trojan" ]]; then
        cat > ${configV2rayPath}/clientConfig.json <<-EOF
=========== ${promptInfoXrayInstall}????????? VLess-TCP-TLS ???????????? =============
{
    ??????: VLess,
    ??????: ${configSSLDomain},
    ??????: ${configV2rayPort},
    uuid: ${v2rayPassword1},
    ??????id: 0,  // AlterID ?????????Vless????????????????????????
    ??????flow: xtls-rprx-direct
    ????????????: none,  // ?????????Vless????????????none
    ????????????: tcp ,
    websocket??????:???,
    ??????????????????:xtls, 
    ??????:????????????????????????
}

????????????:
vless://${v2rayPassUrl}@${configSSLDomain}:${configV2rayPort}?encryption=none&security=xtls&type=tcp&host=${configSSLDomain}&headerType=none&flow=xtls-rprx-direct#${configSSLDomain}


=========== ${promptInfoXrayInstall}????????? VLess-WS-TLS ???????????? ??????CDN =============
{
    ??????: VLess,
    ??????: ${configSSLDomain},
    ??????: ${configV2rayPort},
    uuid: ${v2rayPassword1},
    ??????id: 0,  // AlterID ?????????Vless????????????????????????
    ??????flow: ???
    ????????????: none,  // ?????????Vless????????????none
    ????????????: websocket,
    websocket??????:/${configV2rayWebSocketPath},
    ????????????:tls,     
    ??????:????????????????????????
}

????????????:
vless://${v2rayPassUrl}@${configSSLDomain}:${configV2rayPort}?encryption=none&security=tls&type=ws&host=${configSSLDomain}&path=%2f${configV2rayWebSocketPath}#${configSSLDomain}+ws%E5%8D%8F%E8%AE%AE

EOF
    fi



    if [[ "$configV2rayVlessMode" == "vlessxtlstrojan" ]]; then
    cat > ${configV2rayPath}/clientConfig.json <<-EOF
=========== ${promptInfoXrayInstall}????????? VLess-TCP-TLS ???????????? =============
{
    ??????: VLess,
    ??????: ${configSSLDomain},
    ??????: ${configV2rayPort},
    uuid: ${v2rayPassword1},
    ??????id: 0,  // AlterID ?????????Vless????????????????????????
    ??????flow: xtls-rprx-direct
    ????????????: none,  
    ????????????: tcp ,
    websocket??????:???,
    ??????????????????:xtls, 
    ??????:????????????????????????
}

????????????:
vless://${v2rayPassUrl}@${configSSLDomain}:${configV2rayPort}?encryption=none&security=xtls&type=tcp&host=${configSSLDomain}&headerType=none&flow=xtls-rprx-direct#${configSSLDomain}


=========== ${promptInfoXrayInstall}????????? VLess-WS-TLS ???????????? ??????CDN =============
{
    ??????: VLess,
    ??????: ${configSSLDomain},
    ??????: ${configV2rayPort},
    uuid: ${v2rayPassword1},
    ??????id: 0,  // AlterID ?????????Vless????????????????????????
    ??????flow: ???, 
    ????????????: none,  
    ????????????: websocket,
    websocket??????:/${configV2rayWebSocketPath},
    ????????????:tls,     
    ??????:????????????????????????
}

????????????:
vless://${v2rayPassUrl}@${configSSLDomain}:${configV2rayPort}?encryption=none&security=tls&type=ws&host=${configSSLDomain}&path=%2f${configV2rayWebSocketPath}#${configSSLDomain}+ws%E5%8D%8F%E8%AE%AE



Trojan${promptInfoTrojanName}???????????????: ${configSSLDomain}  ??????: $configV2rayPort

??????1: ${trojanPassword1}
??????2: ${trojanPassword2}
??????3: ${trojanPassword3}
??????4: ${trojanPassword4}
??????5: ${trojanPassword5}
??????6: ${trojanPassword6}
??????7: ${trojanPassword7}
??????8: ${trojanPassword8}
??????9: ${trojanPassword9}
??????10: ${trojanPassword10}
???????????????????????????20???: ??? ${configTrojanPasswordPrefixInput}202001 ??? ${configTrojanPasswordPrefixInput}202020 ???????????????
??????: ??????:${configTrojanPasswordPrefixInput}202002 ??? ??????:${configTrojanPasswordPrefixInput}202019 ???????????????


???????????????:
trojan://${trojanPassword1}@${configSSLDomain}:${configV2rayPort}?peer=${configSSLDomain}&sni=${configSSLDomain}#${configSSLDomain}_trojan

????????? Trojan${promptInfoTrojanName}
https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3a%2f%2f${trojanPassword1}%40${configSSLDomain}%3a${configV2rayPort}%3fpeer%3d${configSSLDomain}%26sni%3d${configSSLDomain}%23${configSSLDomain}_trojan


EOF
    fi



    # ?????? cron ????????????
    # https://stackoverflow.com/questions/610839/how-can-i-programmatically-create-a-new-cron-job

    (crontab -l ; echo "20 4 * * 0,1,2,3,4,5,6 systemctl restart ${promptInfoXrayName}.service") | sort - | uniq - | crontab -


    green "======================================================================"
    green "    ${promptInfoXrayInstall} Version: ${promptInfoXrayVersion} ???????????? !"

    if [[ ${isInstallNginx} == "true" ]]; then
        green "    ??????????????? https://${configSSLDomain}!"
	    green "    ?????????????????????html????????????????????? ${configWebsitePath}, ???????????????????????????!"
    fi
	
	red "    ${promptInfoXrayInstall} ???????????????????????? ${configV2rayPath}/config.json !"
	green "    ${promptInfoXrayInstall} ???????????? ${configV2rayAccessLogFilePath} !"
	green "    ${promptInfoXrayInstall} ???????????? ${configV2rayErrorLogFilePath} ! "
	green "    ${promptInfoXrayInstall} ??????????????????: journalctl -n 50 -u ${promptInfoXrayName}.service "
	green "    ${promptInfoXrayInstall} ????????????: systemctl stop ${promptInfoXrayName}.service  ????????????: systemctl start ${promptInfoXrayName}.service  ????????????: systemctl restart ${promptInfoXrayName}.service"
	green "    ${promptInfoXrayInstall} ????????????????????????:  systemctl status ${promptInfoXrayName}.service "
	green "    ${promptInfoXrayInstall} ????????? ?????????????????????, ??????????????????. ?????? crontab -l ?????? ???????????????????????? !"
	green "======================================================================"
	echo ""
	yellow "${promptInfoXrayInstall} ??????????????????, ?????????????????????, ?????????????????? (???????????????ID???UUID) !!"
	yellow "???????????????: ${configSSLDomain}  ??????: ${configV2rayPortShowInfo}"
	yellow "??????ID?????????1: ${v2rayPassword1}"
	yellow "??????ID?????????2: ${v2rayPassword2}"
	yellow "??????ID?????????3: ${v2rayPassword3}"
	yellow "??????ID?????????4: ${v2rayPassword4}"
	yellow "??????ID?????????5: ${v2rayPassword5}"
	yellow "??????ID?????????6: ${v2rayPassword6}"
	yellow "??????ID?????????7: ${v2rayPassword7}"
	yellow "??????ID?????????8: ${v2rayPassword8}"
	yellow "??????ID?????????9: ${v2rayPassword9}"
	yellow "??????ID?????????10: ${v2rayPassword10}"
    echo ""
	cat "${configV2rayPath}/clientConfig.json"
	echo ""
    green "======================================================================"
    green "?????????????????? ${promptInfoXrayName} ?????????:"
    yellow "1 Windows ?????????V2rayN?????????http://${configSSLDomain}/download/${configTrojanWindowsCliPrefixPath}/v2ray-windows.zip"
    yellow "2 MacOS ??????????????????http://${configSSLDomain}/download/${configTrojanWindowsCliPrefixPath}/v2ray-mac.zip"
    yellow "3 Android ??????????????? https://github.com/2dust/v2rayNG/releases"
    #yellow "3 Android ??????????????? http://${configSSLDomain}/download/${configTrojanWindowsCliPrefixPath}/v2ray-android.zip"
    yellow "4 iOS ????????? ?????????????????? https://shadowsockshelp.github.io/ios/ "
    yellow "  iOS ????????????????????????????????? https://lueyingpro.github.io/shadowrocket/index.html "
    yellow "  iOS ??????????????????????????? ?????? https://github.com/shadowrocketHelp/help/ "
    yellow "??????????????????????????? https://www.v2fly.org/awesome/tools.html "
    green "======================================================================"

    cat >> ${configReadme} <<-EOF




${promptInfoXrayInstall} Version: ${promptInfoXrayVersion} ???????????? ! 
${promptInfoXrayInstall} ???????????????????????? ${configV2rayPath}/config.json 

${promptInfoXrayInstall} ???????????? ${configV2rayAccessLogFilePath}
${promptInfoXrayInstall} ???????????? ${configV2rayErrorLogFilePath}

${promptInfoXrayInstall} ??????????????????: journalctl -n 50 -u ${promptInfoXrayName}.service

${promptInfoXrayInstall} ????????????: systemctl start ${promptInfoXrayName}.service  
${promptInfoXrayInstall} ????????????: systemctl stop ${promptInfoXrayName}.service  
${promptInfoXrayInstall} ????????????: systemctl restart ${promptInfoXrayName}.service
${promptInfoXrayInstall} ????????????????????????:  systemctl status ${promptInfoXrayName}.service 

${promptInfoXrayInstall} ??????????????????, ?????????????????????, ?????????????????? (???????????????ID???UUID) !

???????????????: ${configSSLDomain}  
??????: ${configV2rayPortShowInfo}
??????ID?????????1: ${v2rayPassword1}
??????ID?????????2: ${v2rayPassword2}
??????ID?????????3: ${v2rayPassword3}
??????ID?????????4: ${v2rayPassword4}
??????ID?????????5: ${v2rayPassword5}
??????ID?????????6: ${v2rayPassword6}
??????ID?????????7: ${v2rayPassword7}
??????ID?????????8: ${v2rayPassword8}
??????ID?????????9: ${v2rayPassword9}
??????ID?????????10: ${v2rayPassword10}



EOF

    cat "${configV2rayPath}/clientConfig.json" >> ${configReadme}
}
    

function removeV2ray(){
    if [ -f "${configV2rayPath}/xray" ]; then
        promptInfoXrayName="xray"
        isXray="yes"
    fi

    echo
    green " ================================================== "
    red " ????????????????????? ${promptInfoXrayName} "
    green " ================================================== "
    echo

    ${sudoCmd} systemctl stop ${promptInfoXrayName}.service
    ${sudoCmd} systemctl disable ${promptInfoXrayName}.service


    rm -rf ${configV2rayPath}
    rm -f ${osSystemMdPath}${promptInfoXrayName}.service
    rm -f ${configV2rayAccessLogFilePath}
    rm -f ${configV2rayErrorLogFilePath}

    echo
    green " ================================================== "
    green "  ${promptInfoXrayName} ???????????? !"
    green " ================================================== "
    echo
}


function upgradeV2ray(){
    if [ -f "${configV2rayPath}/xray" ]; then
        promptInfoXrayName="xray"
        isXray="yes"
    fi

    if [ "$isXray" = "no" ] ; then
        getTrojanAndV2rayVersion "v2ray"
        green " =================================================="
        green "       ???????????? V2ray Version: ${versionV2ray} !"
        green " =================================================="
    else
        getTrojanAndV2rayVersion "xray"
        green " =================================================="
        green "       ???????????? Xray Version: ${versionXray} !"
        green " =================================================="
    fi



    ${sudoCmd} systemctl stop ${promptInfoXrayName}.service

    mkdir -p ${configDownloadTempPath}/upgrade/${promptInfoXrayName}

    if [ "$isXray" = "no" ] ; then
        downloadAndUnzip "https://github.com/v2fly/v2ray-core/releases/download/v${versionV2ray}/${downloadFilenameV2ray}" "${configDownloadTempPath}/upgrade/${promptInfoXrayName}" "${downloadFilenameV2ray}"
        mv -f ${configDownloadTempPath}/upgrade/${promptInfoXrayName}/v2ctl ${configV2rayPath}
    else
        downloadAndUnzip "https://github.com/XTLS/Xray-core/releases/download/v${versionXray}/${downloadFilenameXray}" "${configDownloadTempPath}/upgrade/${promptInfoXrayName}" "${downloadFilenameXray}"
    fi

    mv -f ${configDownloadTempPath}/upgrade/${promptInfoXrayName}/${promptInfoXrayName} ${configV2rayPath}
    mv -f ${configDownloadTempPath}/upgrade/${promptInfoXrayName}/geoip.dat ${configV2rayPath}
    mv -f ${configDownloadTempPath}/upgrade/${promptInfoXrayName}/geosite.dat ${configV2rayPath}

    ${sudoCmd} chmod +x ${configV2rayPath}/${promptInfoXrayName}
    ${sudoCmd} systemctl start ${promptInfoXrayName}.service


    if [ "$isXray" = "no" ] ; then
        green " ================================================== "
        green "     ???????????? V2ray Version: ${versionV2ray} !"
        green " ================================================== "
    else
        getTrojanAndV2rayVersion "xray"
        green " =================================================="
        green "     ???????????? Xray Version: ${versionXray} !"
        green " =================================================="
    fi
}













































function installTrojanWeb(){
    # wget -O trojan-web_install.sh -N --no-check-certificate "https://raw.githubusercontent.com/Jrohy/trojan/master/install.sh" && chmod +x trojan-web_install.sh && ./trojan-web_install.sh

    if [ -f "${configTrojanWebPath}/trojan-web" ] ; then
        green " =================================================="
        green "  ???????????? Trojan-web ?????????????????????, ???????????? !"
        green " =================================================="
        exit
    fi

    stopServiceNginx
    testLinuxPortUsage
    installPackage

    green " ================================================== "
    yellow " ?????????????????????VPS????????? ??????www.xxx.com: (??????????????????CDN?????????)"
    green " ================================================== "

    read configSSLDomain
    if compareRealIpWithLocalIp "${configSSLDomain}" ; then

        getTrojanAndV2rayVersion "trojan-web"
        green " =================================================="
        green "    ???????????? Trojan-web ?????????????????????: ${versionTrojanWeb} !"
        green " =================================================="

        # https://github.com/Jrohy/trojan/releases/download/v2.10.4/trojan-linux-amd64
        mkdir -p ${configTrojanWebPath}
        wget -O ${configTrojanWebPath}/trojan-web --no-check-certificate "https://github.com/Jrohy/trojan/releases/download/v${versionTrojanWeb}/${downloadFilenameTrojanWeb}"
        chmod +x ${configTrojanWebPath}/trojan-web


        # ??????????????????
        cat > ${osSystemMdPath}trojan-web.service <<-EOF
[Unit]
Description=trojan-web
Documentation=https://github.com/Jrohy/trojan
After=network.target network-online.target nss-lookup.target mysql.service mariadb.service mysqld.service docker.service

[Service]
Type=simple
StandardError=journal
ExecStart=${configTrojanWebPath}/trojan-web web -p ${configTrojanWebPort}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF

        ${sudoCmd} systemctl daemon-reload
        ${sudoCmd} systemctl enable trojan-web.service
        ${sudoCmd} systemctl start trojan-web.service

        green " =================================================="
        green " Trojan-web ?????????????????????: ${versionTrojanWeb} ????????????!"
        green " Trojan??????????????????????????? https://${configSSLDomain}/${configTrojanWebNginxPath}"
        green " ?????????????????? ${configTrojanWebPath}/trojan-web ?????????????????????."
        green " =================================================="



        ${configTrojanWebPath}/trojan-web

        installWebServerNginx "trojan-web"

        # ????????????????????????
        echo "export PATH=$PATH:${configTrojanWebPath}" >> ${HOME}/.${osSystemShell}rc

        # (crontab -l ; echo '25 0 * * * "${configSSLAcmeScriptPath}"/acme.sh --cron --home "${configSSLAcmeScriptPath}" > /dev/null') | sort - | uniq - | crontab -
        (crontab -l ; echo "30 4 * * 0,1,2,3,4,5,6 systemctl restart trojan-web.service") | sort - | uniq - | crontab -

    else
        exit
    fi
}


function removeTrojanWeb(){
    # wget -O trojan-web_install.sh -N --no-check-certificate "https://raw.githubusercontent.com/Jrohy/trojan/master/install.sh" && chmod +x trojan-web_install.sh && ./trojan-web_install.sh --remove

    green " ================================================== "
    red " ????????????????????? Trojan-web "
    green " ================================================== "

    ${sudoCmd} systemctl stop trojan.service
    ${sudoCmd} systemctl stop trojan-web.service
    ${sudoCmd} systemctl disable trojan-web.service
    

    # ??????trojan
    rm -rf /usr/bin/trojan
    rm -rf /usr/local/etc/trojan
    rm -f ${osSystemMdPath}trojan.service
    rm -f /etc/systemd/system/trojan.service
    rm -f /usr/local/etc/trojan/config.json


    # ??????trojan web ???????????? 
    # rm -f /usr/local/bin/trojan
    rm -rf ${configTrojanWebPath}
    rm -f ${osSystemMdPath}trojan-web.service
    rm -rf /var/lib/trojan-manager

    ${sudoCmd} systemctl daemon-reload


    # ??????trojan??????????????????
    docker rm -f trojan-mysql
    docker rm -f trojan-mariadb
    rm -rf /home/mysql
    rm -rf /home/mariadb


    # ??????????????????
    sed -i '/trojan/d' ${HOME}/.${osSystemShell}rc
    # source ${HOME}/.${osSystemShell}rc

    crontab -r

    green " ================================================== "
    green "  Trojan-web ???????????? !"
    green " ================================================== "
}

function upgradeTrojanWeb(){
    getTrojanAndV2rayVersion "trojan-web"
    green " =================================================="
    green "    ???????????? Trojan-web ?????????????????????: ${versionTrojanWeb} !"
    green " =================================================="

    ${sudoCmd} systemctl stop trojan-web.service

    mkdir -p ${configDownloadTempPath}/upgrade/trojan-web

    wget -O ${configDownloadTempPath}/upgrade/trojan-web/trojan-web "https://github.com/Jrohy/trojan/releases/download/v${versionTrojanWeb}/${downloadFilenameTrojanWeb}"
    mv -f ${configDownloadTempPath}/upgrade/trojan-web/trojan-web ${configTrojanWebPath}
    chmod +x ${configTrojanWebPath}/trojan-web

    ${sudoCmd} systemctl start trojan-web.service
    ${sudoCmd} systemctl restart trojan.service


    green " ================================================== "
    green "     ???????????? Trojan-web ?????????????????????: ${versionTrojanWeb} !"
    green " ================================================== "
}
function runTrojanWebSSL(){
    ${sudoCmd} systemctl stop trojan-web.service
    ${sudoCmd} systemctl stop nginx.service
    ${sudoCmd} systemctl stop trojan.service
    ${configTrojanWebPath}/trojan-web tls
    ${sudoCmd} systemctl start trojan-web.service
    ${sudoCmd} systemctl start nginx.service
    ${sudoCmd} systemctl restart trojan.service
}
function runTrojanWebLog(){
    ${configTrojanWebPath}/trojan-web
}




























function installXUI(){

    stopServiceNginx
    testLinuxPortUsage
    installPackage

    green " ================================================== "
    yellow " ?????????????????????VPS????????? ??????www.xxx.com: (??????????????????CDN?????????)"
    green " ================================================== "

    read configSSLDomain
    if compareRealIpWithLocalIp "${configSSLDomain}" ; then

        green " =================================================="
        green "    ???????????? X-UI ????????????????????? !"
        green " =================================================="

        wget -O x_ui_install.sh -N --no-check-certificate "https://raw.githubusercontent.com/sprov065/x-ui/master/install.sh" && chmod +x x_ui_install.sh && ./x_ui_install.sh

        green "X-UI ??????????????????????????? http://${configSSLDomain}:54321"
        green " ????????? 54321 ??????????????????, ????????????linux????????????VPS????????? 54321 ??????????????????"
        green "X-UI ????????????????????? ????????????????????? admin ?????? admin, ???????????????,???????????????????????????????????? "
        green " =================================================="

    else
        exit
    fi
}
function removeXUI(){
    green " =================================================="
    /usr/bin/x-ui
}


function installV2rayUI(){

    stopServiceNginx
    testLinuxPortUsage
    installPackage

    green " ================================================== "
    yellow " ?????????????????????VPS????????? ??????www.xxx.com: (??????????????????CDN?????????)"
    green " ================================================== "

    read configSSLDomain
    if compareRealIpWithLocalIp "${configSSLDomain}" ; then

        green " =================================================="
        green "    ???????????? V2ray-UI ????????????????????? !"
        green " =================================================="

        wget -O v2_ui_install.sh -N --no-check-certificate "https://raw.githubusercontent.com/sprov065/v2-ui/master/install.sh" && chmod +x v2_ui_install.sh && ./v2_ui_install.sh

        green " V2ray-UI ??????????????????????????? http://${configSSLDomain}:65432"
        green " ????????? 65432 ??????????????????, ????????????linux????????????VPS????????? 65432 ??????????????????"
        green " V2ray-UI ????????????????????? ????????????????????? admin ?????? admin, ???????????????,???????????????????????????????????? "
        green " =================================================="

    else
        exit
    fi
}
function removeV2rayUI(){
    green " =================================================="
    /usr/bin/v2-ui
}
function upgradeV2rayUI(){
    green " =================================================="
    /usr/bin/v2-ui
}















function getHTTPSNoNgix(){
    #stopServiceNginx
    #testLinuxPortUsage

    installPackage

    green " ================================================== "
    yellow " ?????????????????????VPS????????? ??????www.xxx.com: (??????????????????CDN??????nginx????????? ??????80????????????????????????????????????)"
    green " ================================================== "

    read configSSLDomain

    isDomainSSLRequestInput="y"

    isInstallNginx="false"

    if compareRealIpWithLocalIp "${configSSLDomain}" ; then
        if [[ $isDomainSSLRequestInput == [Yy] ]]; then

            echo
            isDomainSSLWebrootInput="y"
            if [[ $isDomainSSLWebrootInput == [Yy] ]]; then
                getHTTPSCertificate "standalone"
            else
                getHTTPSCertificate "webroot"
            fi
            
        else
            green " =================================================="
            green "   ????????????????????????, ??????????????????????????????, ???????????????trojan???v2ray??????!"
            green " ${configSSLDomain} ?????????????????????????????? ${configSSLCertPath}/${configSSLCertFullchainFilename} "
            green " ${configSSLDomain} ?????????????????????????????? ${configSSLCertPath}/${configSSLCertKeyFilename} "
            green " =================================================="
        fi
    else
        exit
    fi


    if test -s ${configSSLCertPath}/${configSSLCertFullchainFilename}; then
        green " =================================================="
        green "   ??????SSL?????????????????? !"
        green " ${configSSLDomain} ?????????????????????????????? ${configSSLCertPath}/${configSSLCertFullchainFilename} "
        green " ${configSSLDomain} ?????????????????????????????? ${configSSLCertPath}/${configSSLCertKeyFilename} "
        green " =================================================="

        if [[ $1 == "trojan" ]] ; then
            installTrojanServer

        elif [[ $1 == "both" ]] ; then
            installV2ray
            installTrojanServer
        else
            installV2ray
        fi        

    else
        red " ================================================== "
        red " https???????????????????????????????????????!"
        red " ??????????????????DNS????????????, ??????????????????????????????????????????!"
        red " ?????????80???443??????????????????, VPS?????????????????????????????????????????????????????????????????????????????????!"
        red " ??????VPS, ??????????????????, ??????????????????????????????????????? ! "
        red " ================================================== "
        exit
    fi



}



function start_menu(){

    if [[ $1 == "first" ]] ; then
        getLinuxOSRelease
        installSoftDownload
    fi

    green " ===================================================================================================="
    green " Trojan Trojan-go V2ray Xray ?????????????????? | 2021-07-22 | By jinwyp | ???????????????centos7+ / debian9+ / ubuntu16.04+"
    red " *????????????????????????????????????????????? ??????????????????????????????80???443??????"
    green " ===================================================================================================="
    green " 1. ??????linux?????? bbr plus, ??????WireGuard, ???????????? Netflix ????????????????????? Google reCAPTCHA ????????????"
    echo
    green " 2. ?????? trojan ??? nginx ?????????CDN, trojan ?????????443??????"
    green " 3. ?????? trojan ???????????????"
    red " 4. ?????? trojan ??? nginx"
    echo
    green " 5. ?????? trojan-go ??? nginx ?????????CDN, ?????????websocket (??????trojan?????????), trojan-go ?????????443??????"
    green " 6. ?????? trojan-go ??? nginx ??????CDN ??????websocket (??????trojan?????????????????????websocket), trojan-go ?????????443??????"
    green " 7. ?????? trojan-go ???????????????"
    red " 8. ?????? trojan-go ??? nginx"
    echo
    green " 11. ?????? v2ray???xray ??? nginx, ?????? websocket tls1.3, ??????CDN, nginx ?????????443??????"
    green " 12. ?????? v2ray???xray ??? nginx, ?????? gRPC http2, ??????CDN, nginx ?????????443??????"
    green " 13. ?????? v2ray???xray ??? nginx, ?????? websocket + gRPC http2, ??????CDN, nginx ?????????443??????"
    green " 14. ?????? xray ??? nginx, (VLess-TCP-XTLS direct) + (VLess-WS-TLS) + xray?????????trojan, ??????CDN, xray ?????????443??????"  
    green " 15. ?????? v2ray???xray ???????????????"
    red " 16. ??????v2ray???xray ??? nginx"
    echo
    green " 21. ???????????? trojan + v2ray???xray ??? nginx, ?????????CDN, trojan ?????????443??????"
    green " 22. ?????? v2ray???xray ??? trojan ???????????????"
    red " 23. ?????? trojan, v2ray???xray ??? nginx"
    echo
    green " 24. ???????????? trojan-go + v2ray???xray ??? nginx, trojan-go?????????CDN, v2ray???xray ??????CDN, trojan-go ?????????443??????"
    green " 25. ???????????? trojan-go + v2ray???xray ??? nginx, trojan-go ??? v2ray ?????????CDN, trojan-go ?????????443??????"
    green " 26. ?????? v2ray???xray ??? trojan-go ???????????????"
    red " 27. ?????? trojan-go, v2ray???xray ??? nginx"
    echo
    green " 28. ????????????????????????????????????????????????"
    green " 29. ????????? ?????? trojan ??? v2ray ?????????????????????, ???????????????, Netflix ????????????, ?????????????????????"
    green " 30. ?????????nginx, ?????????trojan???v2ray???xray, ????????????SSL??????, ??????????????????????????????????????????"
    green " =================================================="
    green " 31. ??????OhMyZsh?????????zsh-autosuggestions, Micro????????? ?????????"
    green " 32. ??????root??????SSH??????, ????????????????????????root??????,????????????????????????"
    green " 33. ??????SSH ???????????????"
    green " 34. ???????????????????????????"
    green " 35. ??? VI ?????? authorized_keys ??????, ??????????????????, ???????????????, ???????????????"
    green " 88. ????????????"
    green " 0. ????????????"
    echo
    read -p "???????????????:" menuNumberInput
    case "$menuNumberInput" in
        1 )
            installWireguard
        ;;
        2 )
            installTrojanV2rayWithNginx
        ;;
        3 )
            upgradeTrojan
        ;;
        4 )
            removeNginx
            removeTrojan
        ;;
        5 )
            isTrojanGo="yes"
            installTrojanV2rayWithNginx
        ;;
        6 )
            isTrojanGo="yes"
            isTrojanGoSupportWebsocket="true"
            installTrojanV2rayWithNginx
        ;;
        7 )
            isTrojanGo="yes"
            upgradeTrojan
        ;;
        8 )
            isTrojanGo="yes"
            removeNginx
            removeTrojan
        ;;
        11 )
            isNginxWithSSL="yes"
            installTrojanV2rayWithNginx "v2ray"
        ;;
        12 )
            isNginxWithSSL="yes"
            configV2rayWSorGrpc="grpc"
            installTrojanV2rayWithNginx "v2ray"
        ;;
        13 )
            isNginxWithSSL="yes"
            configV2rayWSorGrpc="wsgrpc"
            installTrojanV2rayWithNginx "v2ray"
        ;;
        14 )
            configV2rayVlessMode="vlessxtlstrojan"
            installTrojanV2rayWithNginx "v2ray"
        ;;        
        15 )
            upgradeV2ray
        ;;
        16 )
            removeNginx
            removeV2ray
        ;;
        21 )
            installTrojanV2rayWithNginx "both"
        ;;
        22 )
            upgradeTrojan
            upgradeV2ray
        ;;
        23 )
            removeNginx
            removeTrojan
            removeV2ray
        ;;
        24 )
            isTrojanGo="yes"
            installTrojanV2rayWithNginx "both"
        ;;
        25 )
            isTrojanGo="yes"
            isTrojanGoSupportWebsocket="true"
            installTrojanV2rayWithNginx "both"
        ;;
        26 )
            isTrojanGo="yes"
            upgradeTrojan
            upgradeV2ray
        ;;
        27 )
            isTrojanGo="yes"
            removeNginx
            removeTrojan
            removeV2ray
        ;;
        28 )
            cat "${configReadme}"
        ;;        
        31 )
            setLinuxDateZone
            installPackage
            installSoftEditor
            installSoftOhMyZsh
        ;;
        32 )
            setLinuxRootLogin
            sleep 4s
            start_menu
        ;;
        33 )
            changeLinuxSSHPort
            sleep 10s
            start_menu
        ;;
        34 )
            setLinuxDateZone
            sleep 4s
            start_menu
        ;;
        35 )
            editLinuxLoginWithPublicKey
        ;;                 
        29 )
            startMenuOther
        ;;
        30 )
            startMenuOther
        ;;        
        81 )
            installBBR
        ;;
        82 )
            installBBR2
        ;;        
        83 )
            installPackage
        ;;
        88 )
            upgradeScript
        ;;
        99 )
            getTrojanAndV2rayVersion "trojan"
            getTrojanAndV2rayVersion "trojan-go"
            getTrojanAndV2rayVersion "trojan-web"
            getTrojanAndV2rayVersion "v2ray"
            getTrojanAndV2rayVersion "xray"
            getTrojanAndV2rayVersion "wgcf"
        ;;
        0 )
            exit 1
        ;;
        * )
            clear
            red "????????????????????? !"
            sleep 2s
            start_menu
        ;;
    esac
}

start_menu "first"
