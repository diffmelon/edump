#ifndef PUBLIC_H
#define PUBLIC_H


#include <stdio.h>
#include <sys/types.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <pcap.h>
#include <sys/socket.h>     //网络编程常用头文件
#include <arpa/inet.h>       //网络编程常用头文件
#include <time.h>

#define LINKTYPE_ETHERNET 1
struct dump_str
{
    char *addr;
    int portnumber;
    int ethnumber;
};

#endif