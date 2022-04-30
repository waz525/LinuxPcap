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
#include "ethertype.h"

char pcapFile[100] ;
char newFile[100] ;
char keyword[100] ;
int type ;
int mStart ;
int mCount ; 

int SearchPcap() ;
int BinaryMatch( const u_char * haystack , const int len_haystack ,  const char * needle , const int len_needle );

void err_sys(const char *errmsg) ;
void ShowVersion( char * version ) ;
void ShowHelp( char * pro_name) ;
