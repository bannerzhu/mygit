#ifndef _STYLE_DNS_H_
#define _STYLE_DNS_H_

#include "dataList.h"



typedef struct _s_style_dns_ 
{
    char protocol;     //1:udp;2:tcp
	char id;
	float percentage;
	int packetLength;
	
	int srcIpAddressRandom;
	char srcIpValue[16];
	unsigned int srcip_s;       //host order
	unsigned int srcip_e;       //host order
	int srcIpMeth;
	
	int srcPortRandom;
	int srcPortValue;
	int srcport_s;              //host order
	int srcport_e;              //host order
	int srcPortMeth;

    unsigned short dnsid_random;
	unsigned short dnsid;
	char opcode;
	char rd;

    char reqname_level;
    char reqname[1024];
    int req_sublen_min;
    int req_sublen_max;
    int req_type;
	
	int dataRandom;
	char dataValue[1024];
	datalist_arr * datals;
	int dataMeth;
	
}s_style_dns;

#endif

