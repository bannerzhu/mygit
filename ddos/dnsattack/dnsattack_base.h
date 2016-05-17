#ifndef __DNSATTACK_BASE_H__
#define __DNSATTACK_BASE_H__



#include "xmlparse.h"
#include "xmlctr.h"
#include "packetTime.h"

#define XMLCONF_ADDRESS "xmlconfig/dns_udpattackconfig.xml"

#define getOnePackageTime 70 //攻击程序中使用:组织一个数据包的平均时间，将影响心跳攻击中发包间隔时间的精确，单位微秒 
#define MAXLENGTH 1486 //最大IP包长1500-14(14Byte以太网头)
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


