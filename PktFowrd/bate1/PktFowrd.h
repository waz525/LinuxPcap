#include <pcap.h>
#include <pcap-bpf.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <ctype.h>
#define LEN_ETHERNET 14

char pcapFile[1000] ;
char inInterface[100] ;
char outInterface[100] ;
int maxCount ;
char filterStr[1000] ;

void PktFowrdFile() ;
void PktFowrdInterface() ;


void err_sys(const char *errmsg) ;
void ShowVersion( char * version ) ;
void ShowHelp( char * pro_name) ;

