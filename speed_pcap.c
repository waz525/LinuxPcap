/******************************************
* capture ip packet
******************************************/
#include <pcap.h>

#include <string.h>  
#include <stdio.h>  
#include <pthread.h>
#include <linux/types.h>  //ulong
#include <netinet/ip.h>  //iphdr
#include <netinet/tcp.h>  //tcphdr


ulong all_pkts;
ulong all_bytes;
ulong all_http;
ulong old_pkts;
ulong old_bytes;
ulong old_http;


int thread_loop_flag = 1;

void print_speed_thread(void *ptr)
{
    int i;
    
    old_pkts = 0;
    old_bytes = 0;
    old_http = 0;
    
    while(thread_loop_flag)
    {
        sleep(1); 
        printf("\nCurrent speed: %8lu pps, %8lu M bps, http: %8lu pps\n", all_pkts - old_pkts, (all_bytes - old_bytes) >> 17, all_http - old_http);
        old_pkts = all_pkts;
        old_bytes = all_bytes;
        old_http = all_http;
    }      
}


//call back by pcap_loop 
void process_pkt(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char* packet_content)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    
    all_pkts++;
    
    iph = (struct iphdr *)(packet_content + 14);    
    all_bytes += ntohs(iph->tot_len);
    
    if(iph->protocol != 0x6)
    {
        return;
    }
    
    tcph = (struct tcphdr *)(packet_content + 34);
    if((ntohs(tcph->source) == 80) || (ntohs(tcph->dest) == 80)) 
    {
        all_http++;
    }
}


int main(int argc, char *argv[])
{
    pthread_t print_tid;
    char *dev;
    pcap_t *pcap_handle;
    char error_content[PCAP_ERRBUF_SIZE];
    char *p;
    
    if(argc != 2)
    {
        printf("Usage: %s dev\n",argv[0]);
        return -1;
    }
    
    
    if(pthread_create(&print_tid, NULL, (void *)print_speed_thread, NULL) != 0)   
    {
        printf("### Error: Can not creat threads!\n");    
        return -1;
    }
    
    dev = argv[1];        
    if((pcap_handle = pcap_open_live(dev, BUFSIZ, 1, 0, error_content)) == NULL)
    {
        printf("Erorr: pcap open failed!\n");
        return;
    }
    
    pcap_loop(pcap_handle, -1, process_pkt, NULL);
    pcap_close(pcap_handle);
    
    
    thread_loop_flag = 0;
    pthread_join(print_tid, NULL);
    
    
    printf("Total : %lu pkts,  %lu bytes, %lu http\n", all_pkts, all_bytes, all_http);
    

    return 0;
}
