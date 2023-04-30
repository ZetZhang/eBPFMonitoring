#!/bin/sh

# 设置要测试的文件路径和大小
FILE_PATH="/home/ichheit/ich/eBPFMonitoring/shell/prometheus"
FILE_SIZE=1024

# 循环读取文件，生成负载
while true
do
  dd if=$FILE_PATH of=/dev/null bs=$FILE_SIZE count=1 >/dev/null 2>&1 &
done

