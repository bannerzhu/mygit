#ifndef _XMLPARSE_H_
#define _XMLPARSE_H_

#include <arpa/inet.h>

#include "dataList.h"
#include "packetTime.h"
#include "style_dns.h"
#include "dnsattack_base.h"

#define int_ntoa(x)     inet_ntoa(*((struct in_addr *)&x))
#define int_aton(x)     inet_addr(x)

typedef struct ddosConfig_st
{
	int mode;                          //1:singal;2:fixed
	datalist_arr *ipls;                //dst ip list
	datalist_arr *portls;              //dst port list
	int startThreadNumber;             //start pthread number
	int sendPacketNumber;              //packet length
	packetTime packetTimels;           //packetTime
	int pulseyn;                       //pluse
	int cycleTime;
	int pulseTime;
	int speed;
	int attackTime;                    //accack time(min)

    s_style_dns style_dns;
    
	/*
	synCon * synStyle;
	udpCon * udpStyle;
	icmpCon * icmpStyle;
	httpCon * httpStyle;
	*/
}ddosConfig;

/********************************************************************************/
/* 读取xml配置文件放入结构体xmlctr_st中                                         */
/* 输入参数:xml文件名                                                           */
/* 输出:结构体xmlctr_s                                                          */
/********************************************************************************/
int parse_doc_root(ddosConfig *ddosc, char *docname);

void destroy_ddosConfig(ddosConfig *ddosc);


#endif
