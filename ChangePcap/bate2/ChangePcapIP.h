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

char oldfile[100] ;
char newfile[100] ;
char oldip[20] ;
char newip[20] ;

int ChangePcapIP() ;
int ChangeIP( u_char *Msg  , int MsgLen )  ;
int IPToChar( char * ip , u_char * rst ) ;
int CompareInt( u_char * str1 , u_char * str2 , int len ) ;
void HeaderChecksum(u_char *Msg ) ; 

void err_sys(const char *errmsg) ;
void ShowVersion( char * version ) ;
void ShowHelp( char * pro_name) ;

