1.General UNIX requirements
1-1.Linux prerequisites
-Shared Memory
kernel.shmmax = PermSize + TempSize + LogBufMB + 64 MB
kernel.shmall = kernel.shmax / Page_Size(getconf PAGE_SIZE 값, 기본은 4096)
OS root user로 /etc/sysctl.conf 파일 수정 수정 후
#sysctl -p 
로 적용