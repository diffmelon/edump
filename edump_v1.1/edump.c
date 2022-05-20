#include "function.h"
#include <stdio.h>

int main(int argc, char *argv[])
{

	int sockfd, i, tag1, tag2 = 0;
	pcap_t *p;
	pcap_dumper_t *pcap_file;

	/* 此字符数组用来保存数据报 */
	unsigned char msg[1600] = {0};

	/* 先扫描一遍，如果有输出文件选项，则准备好文件指针准备输出文件 */
	for (i = 0; i <argc; i++) {
		if (strcmp(argv[i], "-w") == 0) {
			tag2 = i + 1;
			p = pcap_open_dead(LINKTYPE_ETHERNET, 65535);
			pcap_file = pcap_dump_open(p, argv[tag2]);
			break;
		}
	}

	/* SOCK_RAW提供原始网络协议访问 */
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, ntohs(ETH_P_ALL))) < 0) {
            perror("socket error\n");
    }

	while (1) {

		/* 数组初始化 */
		memset(msg, 0, sizeof(msg));

        /* 接收数据报 */
	    if (recvfrom(sockfd, msg, sizeof (msg), 0, NULL, NULL) < 0) {
            perror("recvfrom error");
        }

		unsigned char ip_types;
		//得到协议号
        ip_types = *(msg+23);

		/* tag1用来记录是否匹配成功 */
        tag1 = 0;

	    for (i = 0; i <argc; i++) {
			/* 判断选项来调用函数过滤包 */
			if (strcmp(argv[i], "host") == 0) { 
				if (edump_host_bag(argv[i + 1], msg)) {
					tag1 = 1;
				}else {
					tag1 = 0;
					break;
				}
			} else if (strcmp(argv[i], "port") == 0) {
				if (edump_port_bag(argv[i + 1], msg)) {
					tag1 = 1;
				} else {
					tag1 = 0;
					break;
				}
			} else if (strcmp(argv[i], "-i") == 0) {
				if (edump_dev_bag(argv[i + 1], msg)) {
					tag1 = 1;
				} else {
					tag1 = 0;
					break;
				}
			} else if (strcmp(argv[i], "TCP" ) == 0 || strcmp(argv[i], "tcp" ) == 0 
                    || strcmp(argv[i], "UDP" ) == 0 || strcmp(argv[i], "udp" ) == 0 
                    || strcmp(argv[i], "ICMP" ) == 0 || strcmp(argv[i], "icmp" ) == 0 
                    || strcmp(argv[i], "DHCP" ) == 0 || strcmp(argv[i], "dhcp" ) == 0 ){
                if (edump_protocol_bag(argv[i], msg)) {
					tag1 = 1;
				} else {
					tag1 = 0;
					break;
				}
			}
		}

        /* 如果记录了选项中有-w，则输出到文件中，如果没有-w，则输出到命令窗口中 */
		if (tag1 && tag2) {

			/*包的总长度*/
			int tolength = msg[16] * 16 + msg[17];

			if (ip_types = 6 || ip_types == 1) {    //tcp包或icmp包
				tolength = tolength + 14;
			} else if (ip_types == 17 || ip_types == 3) {   //udp包或dhcp包
				tolength = tolength - 82;
			}
			
			edump_output_file(argv[tag2], msg, tolength, (pcap_dumper_t *)pcap_file);

		} else if (tag1 && !tag2) {
			edump_output_frame(msg);
		}
	
	}
    
	close(sockfd);
	
	
	return 0;
}
