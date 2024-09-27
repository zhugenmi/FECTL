#!/bin/bash

function fsetxattr(){
  command="sudo find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -path /run -prune -o -path /boot/efi -prune -o -path /run/user -prune -o -type f -exec setfattr -n security.authorized -v verified {} +"
  eval $command &
  pid=$!
  frames="/ | \\ -"
  while ps -p $pid > /dev/null;
  do
    for frame in $frames;
    do
      printf "\r$frame Loading..."
      sleep 0.5
    done
  done
  wait $pid
  printf "\n"
}

if [ "$1" == "-start" ]; then
  touch ~/fectl.log
  echo "初始化fectl..."
  sudo cp fectl.sh /usr/local/bin/fectl
  echo "配置vim..."
  sudo cp vimconfig ~/.vimrc
  echo "生成临时文件..."
  touch /tmp/user.log
  whoami >> /tmp/user.log
  echo "配置inotify..."
  sudo apt install inotify-tools
  echo "启动inotify..."
  sudo chmod +x finotify.sh
  sudo nohup ./finotify.sh > ~/fectl.log &
  echo "正在编译模块..."
  sudo make all
  echo "系统环境初始化，请稍等..."
  fsetxattr
  echo "载入模块..."
  sudo insmod fectl_lsm.ko
  echo "fectl 管控程序正在运行中。"
  fectl -help
elif [ "$1" == "-check" ]; then
  getfattr -n security.authorized "$2"
elif [ "$1" == "-setsa" ]; then
  if [ "$2" == "verified" ] || [ "$2" == "none" ]; then
    sudo setfattr -n security.authorized -v "$2" "$3"
  else
    echo "设置的参数只能为 'verified' 或者 'none'。请重试。"
  fi
elif [ "$1" == "-rmsa" ]; then
  sudo setfattr -x security.authorized "$2"
elif [ "$1" == "-dmesg" ]; then
  dmesg | grep "$2" | tail -n 30
elif [ "$1" == "-systat" ]; then
  sudo ./a.out
elif [ "$1" == "-stop" ]; then
  echo "删除模块..."
  sudo rmmod fectl_lsm
  echo "还原vim设置..."
  sudo rm ~/.vimrc
  echo "清除配置文件..."
  rm ~/fectl.log
  rm /tmp/user.log
  echo "暂停inotify..."
  sudo pkill finotify.sh
  echo "恢复系统状态..."
  sudo nohup find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -path /run -prune -o -path /boot/efi -prune -o -path /run/user -prune -o -type f -exec setfattr -x security.authorized {} + > ~/fectl.log &
  echo "清除object文件及可执行文件..."
  sudo make clean
  sudo rm /usr/local/bin/fectl
  echo "fectl 管控程序已停止。"
else
  echo "======================================================================================================================="
  echo "使用说明: $0  "
  echo "fectl -start | -check [filename] | -setsa [savalue] [filename] | -rmsa [filename] | -dmesg [pattern] | -stop"
  echo "  -start 启动监控程序，并将系统中所有除系统文件和目录的普通文件标记为已授权"
  echo "  -check [filename] 查看文件扩展属性security.authorized的值"
  echo "  -setsa [savalue] [filename] 添加文件扩展属性security.authorized，savalue-授权'verified'|未知'none'，filename-文件名"
  echo "  -rmsa [filename] 删除文件扩展属性security.authorized"
  echo "  -dmesg [pattern] 查看系统日志中最近的 30 条消息，后面可包含指定关键字"
  echo "  -systat 查看当前状态，包括CPU利用率、内容利用率和最近一分钟平均负载"
  echo "  -stop 停止监控程序，同时删除系统中所有文件的标记"
  echo "  -help 帮助"
  echo ""
  echo "======================================================================================================================="
fi