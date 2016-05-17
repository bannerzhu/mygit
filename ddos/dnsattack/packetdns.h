#ifndef __PACKETDNS_H__
#define __PACKETDNS_H__

#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "style_dns.h"
#include "dnsattack_base.h"

/*TCPDHeader*/
struct psdhdr_tcp
{
        unsigned int saddr;/*32,IP from address*/
        unsigned int daddr;/*32,ip to address*/       
	unsigned char mbz;/*set empty*/
        unsigned char ptcl;/*protcol style*/
        unsigned short tcpl;/*TCP length*/ 
	struct tcphdr tcpheader;
};
//struct psdhdr_tcp psdtcp_header;
/*UDPDHeader*/
struct psdhdr_udp
{
	unsigned int saddr;/*32,IP from address*/
        unsigned int daddr;/*32,ip to address*/
        unsigned char mbz;/*set empty*/
        unsigned char ptcl;/*protcol style*/
    	unsigned short udpl;/*UDP length*/ 
    	struct udphdr udpheader;
};

typedef struct _dnshdr 
{
	unsigned short dns_id;

	#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned short dns_rd : 1,				
				   dns_TC : 1,
    			   dns_AA : 1,
    			   dns_opcode : 4,
    			   dns_qr : 1,					
    			   dns_rcode : 4,
    			   dns_zero: 3,
    			   dns_ra : 1;
	#elif __BYTE_ORDER == __BIG_ENDIAN			
	unsigned short dns_qr : 1,
                   dns_opcode : 4,
                   dns_AA  : 1,
                   dns_TC : 1,
				   dns_rd : 1,
     			   dns_ra : 1,
	          	   dns_zero:3,
                   dns_rcode: 4;
	#endif
	
	unsigned short dns_num_q;
	unsigned short dns_num_ans;
	unsigned short dns_num_auth;
	unsigned short dns_num_add;
}s_dnshdr;

typedef struct _dns_query_s
{
	//char name[NS_MAXDNAME];
	unsigned short q_type;
	unsigned short q_class;
}s_dns_query;

typedef struct _rr_info
{
    //char name[NS_MAXDNAME];
	unsigned short type;
	unsigned short rr_class;
	unsigned int ttl;
	unsigned short rdlength;
	//const char * rdata;
}s_rr_info;

enum _dns_rcode
{
    e_rc_nodomain,
    e_rc_redirect
};



/*
enum _dns_sec
{
    e_dnsorsec_dns,
    e_dnsorsec_dnssec,
    e_dnsorsec_all
};
*/
enum _dns_qr_
{
    e_qr_q,
    e_qr_a
};


int ip_udp_dns_package(char *dataArrary,s_style_dns *udpConTemp,char *attackipstr,char *attackportstr);

/********************************************************************************/
/* ×éÖ¯TCP_DNS°ü                                                                */
/********************************************************************************/
int tcp_dns_package(char *dataArrary,s_style_dns *httpConTemp);

#endif


