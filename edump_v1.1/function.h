#ifndef FUNCTION_H
#define FUNCTION_H

#include "public.h"


int edump_host_bag(const char *addr, const unsigned char *msg);//判断是否为对应主机的包
int edump_port_bag(const char *portnumber, const unsigned char *msg);//判断是否为对应端口的包
int edump_dev_bag(const char *dev, const unsigned char *msg);//判断是否为对应网络端口的包
int edump_protocol_bag(const char *protocol, const unsigned char *msg);//判断是否为对应网络协议的包
int edump_output_file(const char *filename, const unsigned char *msg, int msg_len, pcap_dumper_t *pcap_file);//将包输出到文件
int edump_output_frame(const unsigned char *msg);//将包输出到屏幕

#endif




