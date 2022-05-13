#include "function.h"


int main(int argc, char *argv[])
{

    struct dump_str tryner;
    int i;
    int sockfd;

    /* msg数组用来接收数据 */
    unsigned char msg[1600];

    /* 创建一个套接字，SOCK_RAW提供原始网络协议访问 */
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, ntohs(ETH_P_ALL))) < 0) {
        sys_err("socket error\n");
    }

    while (1) {
        /* 使用创建的套接字接收数据存储到msg字符数组中 */
        if(recvfrom(sockfd, msg, sizeof (msg), 0, NULL, NULL) < 0) {
                        perror("recvfrom error");
                        exit(1);
        }
        
        /* 扫描选项执行对应选项操作 */
        for (i = 0; i < argc; i++) {
            if (strcmp (argv[i], "host" ) == 0) {
                edump_host_bag(argv[i + 1]);
            } else if (strcmp (argv[i], "port" ) == 0) {
                edump_port_bag(argv[i + 1]);
            } else if (strcmp (argv[i], "-i" ) == 0) {
                edump_dev_bag(argv[i + 1]);
            } else if (strcmp (argv[i], "TCP" ) == 0 || strcmp (argv[i], "tcp" ) == 0 
                          || strcmp (argv[i], "UDP" ) == 0 || strcmp (argv[i], "udp" ) == 0 
                          || strcmp (argv[i], "ICMP" ) == 0 || strcmp (argv[i], "icmp" ) == 0 
                          || strcmp (argv[i], "DHCP" ) == 0 || strcmp (argv[i], "dhcp" ) == 0 ) {
                edump_protocol_bag(argv[i]);
            } else if (strcmp (argv[i], "-w" ) == 0) {
                edump_output_bag(argv[i + 1]);
            }
        }

    close(sockfd);

    return 0;
}