#include "function.h"

static void sys_err(const char *str); //显示错误信息并退出



/* 显示错误信息并退出 */
static void sys_err(const char *str)
{
    perror(str);
    exit(1);
}

/* edump_host_bag实现抓取指定主机的数据包 */
int edump_host_bag(const char *addr, const unsigned char *msg)
{
        unsigned short type;
        unsigned char ip_types;
    
        /* 获取要监听的主机的地址 */
        unsigned char host_ip[16] = {0};

        snprintf(host_ip, sizeof(host_ip), "%s", addr);
                
        /* 获取源ip地址和目标ip地址 */
        char dst_ip[16] = {0};
        char src_ip[16] = {0};

        snprintf(src_ip, sizeof(src_ip), "%u.%u.%u.%u",msg[26],msg[27],msg[28],msg[29]);
        snprintf(dst_ip, sizeof(dst_ip), "%u.%u.%u.%u",msg[30],msg[31],msg[32],msg[33]);


        if ((!strcmp(host_ip, dst_ip)) || (!strcmp(host_ip, src_ip) )){
                return 1;
        } else {
                return 0;
        }
}

/*edump_port_bag实现抓取指定端口的数据包 */
int edump_port_bag(const char *portnumber, const unsigned char *msg)
{
        unsigned char ip_types;

        /* 获得源端口号和目标端口号 */
        unsigned short src_port;
        unsigned short dst_port;
        src_port = ntohs(*(unsigned short*)(msg+34));
        dst_port = ntohs(*(unsigned short*)(msg+36));
      
        /* 将字符型的portnumber变量转换为整形的pn变量 */
        unsigned short pn = atoi(portnumber);

        /* 通过比较输出要监视的端口的数据 */
        if (pn == src_port || pn == dst_port){
                return 1;
        }else {
                return 0;
        }
}

/* 监视指定网络端口的数据包（指定网卡） */
int edump_dev_bag(const char *dev, const unsigned char *msg) 
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;    //用来打开网卡设备
    int count = 0;

    handle = pcap_open_live(dev, 256, 1, 100, errbuf);
    if (handle == NULL){
            pcap_close(handle);
            return 0;
    } else {
            pcap_close(handle);
            return 1;
    }
}

/* 监视指定网络协议的数据包（指定网卡） */
int edump_protocol_bag(const char *protocol, const unsigned char *msg) 
{

                unsigned short type;
                unsigned char ip_types;
                ip_types = *(msg+23);

                if (strcmp(protocol, "TCP") == 0 || strcmp(protocol, "tcp") == 0){
                        if (ip_types == 6){
                                return 1;
                        }
                }else if (strcmp(protocol, "UDP") == 0 || strcmp(protocol, "udp") == 0){
                        if (ip_types == 17){
                                return 1;
                        }
                }else if (strcmp(protocol, "ICMP") == 0 || strcmp(protocol, "icmp") == 0){
                        if (ip_types == 1){
                                return 1;
                        }
                }else if(strcmp(protocol, "DHCP") == 0 || strcmp(protocol, "dhcp") == 0){
                        if (ip_types == 3){
                                return 1;
                        }
                }

        return 0;
}

int edump_output_file(const char *filename, const unsigned char *msg, int msg_len, pcap_dumper_t *pcap_file) //测试保存报文到文件中
{

        /* 初始化时间 */
        clock_t time;

        /* 写包 */
        struct pcap_pkthdr pkt_header;
        time = clock();
        pkt_header.ts.tv_sec = time / CLOCKS_PER_SEC;
        pkt_header.ts.tv_usec = time % CLOCKS_PER_SEC;
        pkt_header.caplen = msg_len;
        pkt_header.len = msg_len;
        pcap_dump((u_char*)pcap_file, &pkt_header, msg);
  
        return 0;
}

int edump_output_frame(const unsigned char *msg)//输出到屏幕
{
        unsigned char ip_types;

         //获取源ip地址和目标ip地址
        unsigned char dst_ip[16] = {0};
        unsigned char src_ip[16] = {0};

        snprintf(src_ip, sizeof(src_ip), "%u.%u.%u.%u", msg[26],msg[27],msg[28],msg[29]);
        snprintf(dst_ip, sizeof(src_ip), "%u.%u.%u.%u", msg[30],msg[31],msg[32],msg[33]);

        //获得源端口号和目标端口号
        unsigned short src_port;
        unsigned short dst_port;

        src_port = ntohs(*(unsigned short*)(msg+34));
        dst_port = ntohs(*(unsigned short*)(msg+36));
 
        //得到协议号
        ip_types = *(msg+23);
        
        printf("IP协议类型为：");

        if (ip_types == 6) {
                printf("TCP");
        } else if (ip_types == 17) {
                printf("UDP");
        } else if (ip_types == 1) {
                printf("ICMP");
        } else if (ip_types == 3) {
                printf("DHCP");
        }        

        printf("\n源IP地址：%s --> 目标ip地址：%s", src_ip, dst_ip);
        printf("\n源端口号为：%d --> 目标端口号为：%d\n",src_port,dst_port);

        printf("\n*************************\n\n");

        return 0;

}
