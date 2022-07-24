#!/bin/sh

if [[ $EUID -ne 0 ]]; then
    clear
    echo "Error: This script must be run as root!" 1>&2
    exit 1
fi

function CopyRight() {
  clear
  echo "########################################################"
  echo "#                                                      #"
  echo "#  New Reinstall Script                                #"
  echo "#                                                      #"
  echo "#  Author: Minijer & hiCasper                          #"
  echo "#  Last Modified: 2022-07-03                           #"
  echo "#                                                      #"
  echo "#  Shell By MoeClub                                    #"
  echo "#                                                      #"
  echo "########################################################"
  echo -e "\n"
}

function isValidIp() {
  local ip=$1
  local ret=1
  if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    ip=(${ip//\./ })
    [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
    ret=$?
  fi
  return $ret
}

function ipCheck() {
  isLegal=0
  for add in $MAINIP $GATEWAYIP $NETMASK; do
    isValidIp $add
    if [ $? -eq 1 ]; then
      isLegal=1
    fi
  done
  return $isLegal
}

function GetIp() {
  MAINIP=$(ip route get 1 | awk -F 'src ' '{print $2}' | awk '{print $1}')
  GATEWAYIP=$(ip route | grep default | awk '{print $3}')
  SUBNET=$(ip -o -f inet addr show | awk '/scope global/{sub(/[^.]+\//,"0/",$4);print $4}' | head -1 | awk -F '/' '{print $2}')
  value=$(( 0xffffffff ^ ((1 << (32 - $SUBNET)) - 1) ))
  NETMASK="$(( (value >> 24) & 0xff )).$(( (value >> 16) & 0xff )).$(( (value >> 8) & 0xff )).$(( value & 0xff ))"
}

function UpdateIp() {
  read -r -p "Your IP: " MAINIP
  read -r -p "Your Gateway: " GATEWAYIP
  read -r -p "Your Netmask: " NETMASK
}

function SetNetwork() {
  isAuto='0'
  if [[ -f '/etc/network/interfaces' ]];then
    [[ ! -z "$(sed -n '/iface.*inet static/p' /etc/network/interfaces)" ]] && isAuto='1'
    [[ -d /etc/network/interfaces.d ]] && {
      cfgNum="$(find /etc/network/interfaces.d -name '*.cfg' |wc -l)" || cfgNum='0'
      [[ "$cfgNum" -ne '0' ]] && {
        for netConfig in `ls -1 /etc/network/interfaces.d/*.cfg`
        do 
          [[ ! -z "$(cat $netConfig | sed -n '/iface.*inet static/p')" ]] && isAuto='1'
        done
      }
    }
  fi
  
  if [[ -d '/etc/sysconfig/network-scripts' ]];then
    cfgNum="$(find /etc/network/interfaces.d -name '*.cfg' |wc -l)" || cfgNum='0'
    [[ "$cfgNum" -ne '0' ]] && {
      for netConfig in `ls -1 /etc/sysconfig/network-scripts/ifcfg-* | grep -v 'lo$' | grep -v ':[0-9]\{1,\}'`
      do 
        [[ ! -z "$(cat $netConfig | sed -n '/BOOTPROTO.*[sS][tT][aA][tT][iI][cC]/p')" ]] && isAuto='1'
      done
    }
  fi
}

function NetMode() {
  CopyRight
  NETSTR=''
}

function Start() {
  CopyRight
  
  isCN='0'
  geoip=$(wget --no-check-certificate -qO- https://api.myip.com | grep "\"country\":\"China\"")
  if [[ "$geoip" != "" ]];then
    isCN='1'
  fi

  if [ "$isAuto" == '0' ]; then
    echo "Using DHCP mode."
  else
    echo "IP: $MAINIP"
    echo "Gateway: $GATEWAYIP"
    echo "Netmask: $NETMASK"
  fi

  [[ "$isCN" == '1' ]] && echo "Using domestic mode."

  if [ -f "/tmp/InstallNET.sh" ]; then
    rm -f /tmp/InstallNET.sh
  fi

  if [[ "$isCN" == '1' ]]; then
   wget --no-check-certificate -qO /tmp/InstallNET.sh 'https://cdn.jsdelivr.net/gh/fcurrk/reinstall@master/InstallNET.sh' && chmod a+x /tmp/InstallNET.sh
  else 
   wget --no-check-certificate -qO /tmp/InstallNET.sh 'https://raw.githubusercontent.com/fcurrk/reinstall/master/InstallNET.sh' && chmod a+x /tmp/InstallNET.sh
  fi
  
  CMIRROR=''
  CVMIRROR=''
  DMIRROR=''
  UMIRROR=''
  SYSMIRROR1='http://disk.29296819.xyz/92shidai.com/dd/os/veip007/CentOS-7.img.gz'
  SYSMIRROR2='http://disk.29296819.xyz/92shidai.com/dd/os/cxthhhhh/CentOS_7.X_NetInstallation_Final.vhd.gz'
  SYSMIRROR3='http://disk.29296819.xyz/92shidai.com/dd/os/cxthhhhh/CentOS_8.X_NetInstallation_Stable_v4.2.vhd.gz'
  SYSMIRROR12='http://disk.29296819.xyz/92shidai.com/dd/os/cxthhhhh/new/Disk_Windows_Server_2019_DataCenter_CN_v5.1.vhd.gz'
  SYSMIRROR13='http://disk.29296819.xyz/92shidai.com/dd/os/cxthhhhh/new/Disk_Windows_Server_2016_DataCenter_CN_v4.12.vhd.gz'
  SYSMIRROR14='http://disk.29296819.xyz/92shidai.com/dd/os/cxthhhhh/new/Disk_Windows_Server_2012R2_DataCenter_CN_v4.29.vhd.gz'
  SYSMIRROR15='http://disk.29296819.xyz/92shidai.com/dd/os/laosiji/WinSrv2012r2x64/guajibao/guajibao-winsrv2012r2-data-x64-cn.vhd.gz'
  SYSMIRROR16='http://disk.29296819.xyz/92shidai.com/dd/os/cxthhhhh/new/Disk_Windows_Server_2008R2_DataCenter_CN_v3.27.vhd.gz'
  SYSMIRROR17='http://disk.29296819.xyz/92shidai.com/dd/os/laosiji/WinSrv2008x64/lite/winsrv2008r2-data-sp1-x64-cn.vhd.gz'
  SYSMIRROR18='http://disk.29296819.xyz/92shidai.com/dd/os/cxthhhhh/new/Disk_Windows_Server_2003_DataCenter_CN_v7.1.vhd.gz'
  SYSMIRROR19='http://disk.29296819.xyz/92shidai.com/dd/os/laosiji/WinSrv2003/10G/WinSrv2003x86-Chinese-C10G.vhd.gz'
  SYSMIRROR20='http://disk.29296819.xyz/92shidai.com/dd/os/laosiji/Win10/guajibao/guajibao-win10-ent-ltsc-2021-x64-cn.vhd.gz'
  SYSMIRROR21='http://disk.29296819.xyz/92shidai.com/dd/os/laosiji/Win7/guajibao/guajibao-win7-sp1-ent-x86-cn.vhd.gz'
  SYSMIRROR22='http://disk.29296819.xyz/92shidai.com/dd/os/laosiji/Win7/guajibao/guajibao-win7-sp1-ent-x64-cn.vhd.gz'
  SYSMIRROR23='http://disk.29296819.xyz/92shidai.com/dd/os/laosiji/Win7/guajibao/guajibao-win7-sp1-ent-x64-cn-efi.vhd.gz'
  SYSMIRROR24='http://disk.29296819.xyz/92shidai.com/dd/os/laosiji/WinSrv2008x64/lite/winsrv2008r2-data-sp1-x64-cn-efi.vhd.gz'
  SYSMIRROR25='http://disk.29296819.xyz/92shidai.com/dd/os/laosiji/WinSrv2012r2x64/guajibao/guajibao-winsrv2012r2-data-x64-cn-efi.vhd.gz'

  if [[ "$isCN" == '1' ]];then
    CMIRROR="--mirror http://mirrors.aliyun.com/centos/"
    CVMIRROR="--mirror http://mirrors.tuna.tsinghua.edu.cn/centos-vault/"
    DMIRROR="--mirror http://mirrors.aliyun.com/debian/"
    UMIRROR="--mirror http://mirrors.aliyun.com/ubuntu/"
    SYSMIRROR1='http://disk.29296819.xyz/92shidai.com/dd/os/veip007/CentOS-7.img.gz'
    SYSMIRROR2='http://disk.29296819.xyz/92shidai.com/dd/os/cxthhhhh/CentOS_7.X_NetInstallation_Final.vhd.gz'
    SYSMIRROR3='http://disk.29296819.xyz/92shidai.com/dd/os/cxthhhhh/CentOS_8.X_NetInstallation_Stable_v4.2.vhd.gz'
    SYSMIRROR12='http://disk.29296819.xyz/92shidai.com/dd/os/cxthhhhh/new/Disk_Windows_Server_2019_DataCenter_CN_v5.1.vhd.gz'
    SYSMIRROR13='http://disk.29296819.xyz/92shidai.com/dd/os/cxthhhhh/new/Disk_Windows_Server_2016_DataCenter_CN_v4.12.vhd.gz'
    SYSMIRROR14='http://disk.29296819.xyz/92shidai.com/dd/os/cxthhhhh/new/Disk_Windows_Server_2012R2_DataCenter_CN_v4.29.vhd.gz'
    SYSMIRROR15='http://disk.29296819.xyz/92shidai.com/dd/os/laosiji/WinSrv2012r2x64/guajibao/guajibao-winsrv2012r2-data-x64-cn.vhd.gz'
    SYSMIRROR16='http://disk.29296819.xyz/92shidai.com/dd/os/cxthhhhh/new/Disk_Windows_Server_2008R2_DataCenter_CN_v3.27.vhd.gz'
    SYSMIRROR17='http://disk.29296819.xyz/92shidai.com/dd/os/laosiji/WinSrv2008x64/lite/winsrv2008r2-data-sp1-x64-cn.vhd.gz'
    SYSMIRROR18='http://disk.29296819.xyz/92shidai.com/dd/os/cxthhhhh/new/Disk_Windows_Server_2003_DataCenter_CN_v7.1.vhd.gz'
    SYSMIRROR19='http://disk.29296819.xyz/92shidai.com/dd/os/laosiji/WinSrv2003/10G/WinSrv2003x86-Chinese-C10G.vhd.gz'
    SYSMIRROR20='http://disk.29296819.xyz/92shidai.com/dd/os/laosiji/Win10/guajibao/guajibao-win10-ent-ltsc-2021-x64-cn.vhd.gz'
    SYSMIRROR21='http://disk.29296819.xyz/92shidai.com/dd/os/laosiji/Win7/guajibao/guajibao-win7-sp1-ent-x86-cn.vhd.gz'
    SYSMIRROR22='http://disk.29296819.xyz/92shidai.com/dd/os/laosiji/Win7/guajibao/guajibao-win7-sp1-ent-x64-cn.vhd.gz'
    SYSMIRROR23='http://disk.29296819.xyz/92shidai.com/dd/os/laosiji/Win7/guajibao/guajibao-win7-sp1-ent-x64-cn-efi.vhd.gz'
    SYSMIRROR24='http://disk.29296819.xyz/92shidai.com/dd/os/laosiji/WinSrv2008x64/lite/winsrv2008r2-data-sp1-x64-cn-efi.vhd.gz'
    SYSMIRROR25='http://disk.29296819.xyz/92shidai.com/dd/os/laosiji/WinSrv2012r2x64/guajibao/guajibao-winsrv2012r2-data-x64-cn-efi.vhd.gz'

  fi
bash /tmp/InstallNET.sh -d 11 -v 64 -p Aa112211 -port 22 $NETSTR $DMIRROR
}

SetNetwork
NetMode
Start
