#ifndef __DNSATTACK_BASE_H__
#define __DNSATTACK_BASE_H__



#include "xmlparse.h"
#include "xmlctr.h"
#include "packetTime.h"

#define XMLCONF_ADDRESS "xmlconfig/dns_udpattackconfig.xml"

#define getOnePackageTime 70 //����������ʹ��:��֯һ�����ݰ���ƽ��ʱ�䣬��Ӱ�����������з������ʱ��ľ�ȷ����λ΢�� 
#define MAXLENGTH 1486 //���IP����1500-14(14Byte��̫��ͷ)
#define MAXSIZE 1024

//#define DEBUG
//#define DEBUG_PRINTF_DOMAIN


enum _dns_rr_type
{
	e_type_a=1,
	e_type_ns=2,
	e_type_cname=5,
	e_type_ptr=12,
	e_type_hinfo=13,
	e_type_mx=15,
	e_type_aaaa=28,
	e_type_opt=29 //opt 
};

#endif


