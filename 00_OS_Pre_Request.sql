1.General UNIX requirements
1-1.Linux prerequisites
-Shared Memory
kernel.shmmax = PermSize + TempSize + LogBufMB + 64 MB
kernel.shmall = kernel.shmax / Page_Size(getconf PAGE_SIZE ��, �⺻�� 4096)
OS root user�� /etc/sysctl.conf ���� ���� ���� ��
#sysctl -p 
�� ����