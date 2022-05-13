#include "public.h"

void sys_err(const char *str);
int edump_host_bag(const char *addr, const char *msg);




void sys_err(const char *str)
{
    perror(str);
    exit(1);
}

//edump_host_bag实现抓取指定主机的数据包
int edump_host_bag(const char *addr, const char *msg)
{
        
        unsigned short type;
        unsigned char ip_types;
    
        //获取要监听的主机的地址
        unsigned char host_ip[16] = "";
        sprintf(host_ip,addr);
                
        //获取源ip地址和目标ip地址
        unsigned char dst_ip[16] = "";
        unsigned char src_ip[16] = "";

        sprintf(src_ip,"%u.%u.%u.%u",msg[26],msg[27],msg[28],msg[29]);
         sprintf(dst_ip,"%u.%u.%u.%u",msg[30],msg[31],msg[32],msg[33]);

        if (!(strcmp(host_ip, dst_ip)) || (!strcmp(host_ip, src_ip) )){
                printf("源ip地址：%s --> 目标ip地址：%s\n",src_ip,dst_ip);
                //得到协议号
                ip_types = *(msg+23);
                printf("ip协议类型为：%d\n",ip_types);
                printf("\n******************\n\n");
        }
         
}

//edump_port_bag实现抓取指定端口的数据包
int edump_port_bag(const char *portnumber, const char *msg)
{
        int sockfd;

        //SOCK_RAW提供原始网络协议访问
        if ((sockfd = socket(AF_PACKET, SOCK_RAW, ntohs(ETH_P_ALL))) < 0){
                sys_err("socket error\n");
        }

        //接受数据并进行分析
        unsigned char msg[1600] = "";     //字符数组初始化，此字符数组用来保存数据报
         while (1) {
                if(recvfrom(sockfd,msg,sizeof (msg),0,NULL,NULL) < 0){
                        perror("recvfrom error");
                        exit(1);
                }

                unsigned char ip_types;

                        //获得源端口号和目标端口号
                        unsigned short src_port;
                        unsigned short dst_port;
                        src_port = ntohs(*(unsigned short*)(msg+34));
                        dst_port = ntohs(*(unsigned short*)(msg+36));
      
                        //将字符型的portnumber变量转换为整形的pn变量
                        unsigned short pn = atoi(portnumber);

                        //通过比较输出要监视的端口的数据
                        if (pn == src_port || pn == dst_port){
                            printf("源端口号为：%d --> 目标端口号为：%d\n",src_port,dst_port);
                             //得到协议号
                            ip_types = *(msg+23);
                            printf("ip协议类型为：%d\n",ip_types);
                            printf("\n******************\n\n");
                        }
         }
         close(sockfd);
}

void processPacket1(u_char *arg, struct pcap_pkthdr *pkthdr, const u_char *packet)
{
        int *count = (int *)arg;
 
    printf("Packet Count: %d\n", ++(*count));
    printf("Received Packet Size: %d\n", pkthdr->len);
    printf("Payload:\n");
 
    for(int i=0; i < pkthdr->len; ++i)      //print
    {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0)
        {
            printf("\n");
        }
    }
    printf("\n\n");
    return;
}

int edump_dev_bag(const char *dev, const char *msg) //监视指定网络端口的数据包（指定网卡）
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;    //用来打开网卡设备
    int count = 0;

    handle = pcap_open_live(dev, 256, 1, 100, errbuf);
    if (handle == NULL){
        perror("打开设备失败，不存在设备\n");
    }

    pcap_loop(handle, -1, processPacket1, (u_char *)&count);

    pcap_close(handle);
    return 0;
}

int edump_protocol_bag(const char *protocol, const char *msg) //监视指定网络协议的数据包（指定网卡）
{
            int sockfd;
        
        //SOCK_RAW提供原始网络协议访问
        if ((sockfd = socket(AF_PACKET, SOCK_RAW, ntohs(ETH_P_ALL))) < 0){
                perror("socket error\n");
                exit(1);
        }

        //接受数据并进行分析
        unsigned char msg[1600] = "";     //字符数组初始化，此字符数组用来保存数据报
        while (1) {
                if(recvfrom(sockfd,msg,sizeof (msg),0,NULL,NULL) < 0){
                        perror("recvfrom error");
                        exit(1);
                }
                 unsigned short type;
                unsigned char ip_types;
                ip_types = *(msg+23);

                if (strcmp(protocol, "TCP") == 0 || strcmp(protocol, "tcp") == 0){
                        if (ip_types == 6){
                                printf("监听获取到TCP报文\n");
                        //获得目标端口号和源端口号
                        unsigned short dst_port;
                        unsigned short src_port;
                        src_port = ntohs(*(unsigned short*)(msg+34));
                        dst_port = ntohs(*(unsigned short*)(msg+36));
                        printf("源端口号为：%d --> 目标端口号为：%d\n",src_port,dst_port);
                        }
                }else if (strcmp(protocol, "UDP") == 0 || strcmp(protocol, "udp") == 0){
                        if (ip_types == 17){
                                printf("监听获取到UDP报文\n");
                        //获得目标端口号和源端口号
                        unsigned short dst_port;
                        unsigned short src_port;
                        src_port = ntohs(*(unsigned short*)(msg+34));
                        dst_port = ntohs(*(unsigned short*)(msg+36));
                        printf("源端口号为：%d --> 目标端口号为：%d\n",src_port,dst_port);
                        }
                }else if (strcmp(protocol, "ICMP") == 0 || strcmp(protocol, "icmp") == 0){
                        if (ip_types == 1){
                                printf("监听获取到ICMP报文\n");
                        //获取源ip地址和目标ip地址
                        unsigned char dst_ip[16] = "";
                        unsigned char src_ip[16] = "";
                        sprintf(src_ip,"%u.%u.%u.%u",msg[28],msg[29],msg[30],msg[31]);
                        sprintf(dst_ip,"%u.%u.%u.%u",msg[38],msg[39],msg[40],msg[41]);
                        printf("源ip地址：%s --> 目标ip地址：%s\n",src_ip,dst_ip);
                        }
                }else if (strcmp(protocol, "ARP") == 0 || strcmp(protocol, "arp") == 0){
                        if (ip_types == 0x0806){
                                printf("监听获取到ARP数据报\n");
                        //获取源ip地址和目标ip地址
                        unsigned char dst_ip[16] = "";
                        unsigned char src_ip[16] = "";
                        sprintf(src_ip,"%u.%u.%u.%u",msg[28],msg[29],msg[30],msg[31]);
                        sprintf(dst_ip,"%u.%u.%u.%u",msg[38],msg[39],msg[40],msg[41]);
                        printf("源ip地址：%s --> 目标ip地址：%s\n",src_ip,dst_ip);
                        }
                }else if (strcmp(protocol, "UDP") == 0 || strcmp(protocol, "udp") == 0){
                        if (ip_types == 0x8035){
                                printf("监听获取到RARP数据报\n");
                        }
                }else if(strcmp(protocol, "DHCP") == 0 || strcmp(protocol, "dhcp") == 0){
                        
                        if (ip_types == 3){
                        printf("监听获取到DHCP报文\n");
                        }
                }        
        }
        close(sockfd);
        return 0;
}

void processPacket2(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) 
{
        pcap_dump(arg, pkthdr, packet); //写*.pcap文件数据
        printf("Received Packet Size: %d\n", pkthdr->len);
        return;
}

int edump_output_bag(const char *filename, const char *msg) //输出到指定文件
{
        char errBuf[PCAP_ERRBUF_SIZE], *devStr;

        devStr = pcap_lookupdev(errBuf);
        if (devStr)
                printf("success: device: %s\n", devStr);
        else
                sys_err("error\n");

        //打开一个设备，阻塞等待直到收到一个包
        pcap_t * device =  pcap_open_live(devStr, 65535, 1, 0, errBuf);
        if (!device){
                printf("error: pcap_open_live(): %s\n", errBuf);
                exit(1);
        }

        //打开准备要输入包到文件的文件
        pcap_dumper_t* out_pcap;
        out_pcap = pcap_dump_open(device, filename);

        //一直循环20次，对每一个收到的包执行processPacket函数
        pcap_loop(device, 20, processPacket2, (u_char *)out_pcap);

        //flush buff
        pcap_dump_flush(out_pcap);

        pcap_dump_close(out_pcap);
        pcap_close(device);

   
    return 0;
}