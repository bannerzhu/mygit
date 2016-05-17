/********************************************************************************/
/* 读取xml配置文件                                                              */
/* author:cp                                                                    */
/* 2012.7.21                                                                    */
/********************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h> 

#include "xmlparse.h"
#include "xmlctr.h"

static int parse_dns_data(ddosConfig *ddosc,s_xmlcnf xmlcnf)
{
    int ret=0;
    char buff[1024];
    ret = xmlcnf_node_getattribute(xmlcnf,"random",buff);
    if(!ret)
    {
        if(!strcmp(buff,"true"))
            ddosc->style_dns.dataRandom=1;
        else
            ddosc->style_dns.dataRandom=0;
    }
    xmlcnf_node_next(&xmlcnf,1);
    while(xmlcnf.cur)
    {
        ret = xmlcnf_node_getvalue(xmlcnf,"value",buff);
        if(!ret)
        {
            strcpy(ddosc->style_dns.dataValue,buff);
            #ifdef DEBUG
            printf("data value[%s]\n",ddosc->style_dns.dataValue);
            #endif
        }
        ret = xmlcnf_node_getvalue(xmlcnf,"scope",buff);
        if(!ret)
        {
            ddosc->style_dns.datals = get_ls_arr(buff);
            #ifdef DEBUG
            printf("data scope[%s]\n",buff);
            #endif
        }
        ret = xmlcnf_node_getvalue(xmlcnf,"meth",buff);
        if(!ret)
        {
            ddosc->style_dns.dataMeth = atoi(buff);
            #ifdef DEBUG
            printf("dns data meth[%d]\n",ddosc->style_dns.dataMeth);
            #endif
        }
        xmlcnf_node_next(&xmlcnf,0);
    }
    return 0;
}
static int parse_dns_reqname(ddosConfig *ddosc,s_xmlcnf xmlcnf)
{
    int ret=0;
    char buff[1024];
    xmlcnf_node_next(&xmlcnf,1);
    while(xmlcnf.cur)
    {
        ret = xmlcnf_node_getvalue(xmlcnf,"level",buff);
        if(!ret)
        {
            ddosc->style_dns.reqname_level = atoi(buff);
            #ifdef DEBUG
            printf("dns reqname level[%d]\n",ddosc->style_dns.reqname_level);
            #endif
        }
        ret = xmlcnf_node_getvalue(xmlcnf,"name",buff);
        if(!ret)
        {
            strcpy(ddosc->style_dns.reqname,buff);
            #ifdef DEBUG
            printf("reqname [%s]\n",ddosc->style_dns.reqname);
            #endif
        }
        ret = xmlcnf_node_getvalue(xmlcnf,"subLen",buff);
        if(!ret)
        {
            char *p=strstr(buff,",");
            int str_f_l=p-buff;
            char str_f[100];
            memcpy(str_f,buff,str_f_l);
            str_f[str_f_l]=0;

            ddosc->style_dns.req_sublen_min = atoi(str_f);
            ddosc->style_dns.req_sublen_max = atoi(p+1);

            if(ddosc->style_dns.req_sublen_min>63)
                ddosc->style_dns.req_sublen_min=1;
            
            if(ddosc->style_dns.req_sublen_max>63)
                ddosc->style_dns.req_sublen_max=63;

            if(ddosc->style_dns.req_sublen_min>ddosc->style_dns.req_sublen_max)
                ddosc->style_dns.req_sublen_min=1;
            #ifdef DEBUG
            printf("subLen [%d]-[%d]\n",ddosc->style_dns.req_sublen_min,ddosc->style_dns.req_sublen_max);
            #endif
        }
        xmlcnf_node_next(&xmlcnf,0);
    }
    return 0;
}
static int parse_dns_header(ddosConfig *ddosc,s_xmlcnf xmlcnf)
{
    int ret=0;
    char buff[1024];
    xmlcnf_node_next(&xmlcnf,1);
    while(xmlcnf.cur)
    {
        ret = xmlcnf_node_getvalue(xmlcnf,"protocol",buff);
        if(!ret)
        {
            if(!strcmp(buff,"tcp"))
                ddosc->style_dns.protocol=2;
            else
                ddosc->style_dns.protocol=1;
        }
        
        ret = xmlcnf_node_getvalue(xmlcnf,"dnsid",buff);
        if(!ret)
        {
            ddosc->style_dns.dnsid_random = atoi(buff);
            #ifdef DEBUG
            printf("dns dnsid[%d]\n",ddosc->style_dns.dnsid_random);
            #endif
        }
        ret = xmlcnf_node_getvalue(xmlcnf,"opcode",buff);
        if(!ret)
        {
            ddosc->style_dns.opcode = atoi(buff);
            #ifdef DEBUG
            printf("dns opcode[%d]\n",ddosc->style_dns.opcode);
            #endif
        }
        ret = xmlcnf_node_getvalue(xmlcnf,"RD",buff);
        if(!ret)
        {
            ddosc->style_dns.rd = atoi(buff);
            #ifdef DEBUG
            printf("dns rd[%d]\n",ddosc->style_dns.rd);
            #endif
        }
        ret = xmlcnf_node_check(xmlcnf,"reqName");
        if(!ret)
        {
            parse_dns_reqname(ddosc,xmlcnf);
            
        }
        ret = xmlcnf_node_getvalue(xmlcnf,"reqType",buff);
        if(!ret)
        {
            if(!strcmp(buff,"A"))
                ddosc->style_dns.req_type= e_type_a;
            else if(!strcmp(buff,"NS"))
                ddosc->style_dns.req_type= e_type_ns;
            else if(!strcmp(buff,"MX"))
                ddosc->style_dns.req_type= e_type_mx;
            else if(!strcmp(buff,"CNAME"))
                ddosc->style_dns.req_type= e_type_cname;
            else if(!strcmp(buff,"AAAA"))
                ddosc->style_dns.req_type= e_type_aaaa;
            else if(!strcmp(buff,"PTR"))
                ddosc->style_dns.req_type= e_type_ptr;
            else
                ddosc->style_dns.req_type= e_type_a;
        }
        xmlcnf_node_next(&xmlcnf,0);
    }
    return 0;
}
static int parse_dns_sport(ddosConfig *ddosc,s_xmlcnf xmlcnf)
{
    int ret=0;
    char buff[1024];
    ret = xmlcnf_node_getattribute(xmlcnf,"random",buff);
    if(!ret)
    {
        if(!strcmp(buff,"true"))
            ddosc->style_dns.srcPortRandom=1;
        else
            ddosc->style_dns.srcPortRandom=0;
    }
    xmlcnf_node_next(&xmlcnf,1);
    while(xmlcnf.cur)
    {
        ret = xmlcnf_node_getvalue(xmlcnf,"value",buff);
        if(!ret)
        {
            ddosc->style_dns.srcPortValue = atoi(buff);
            #ifdef DEBUG
            printf("sport value[%d]\n",ddosc->style_dns.srcPortValue);
            #endif
        }
        ret = xmlcnf_node_getvalue(xmlcnf,"scope",buff);
        if(!ret)
        {
            char *p=strstr(buff,",");
            int str_f_l=p-buff;
            char str_f[100];
            memcpy(str_f,buff,str_f_l);
            str_f[str_f_l]=0;

            ddosc->style_dns.srcport_s = atoi(str_f);
            ddosc->style_dns.srcport_e = atoi(p+1);
            #ifdef DEBUG
            printf("sport scope[%d]-[%d]\n",ddosc->style_dns.srcport_s,ddosc->style_dns.srcport_e);
            #endif
        }
        ret = xmlcnf_node_getvalue(xmlcnf,"meth",buff);
        if(!ret)
        {
            ddosc->style_dns.srcPortMeth = atoi(buff);
        }
        xmlcnf_node_next(&xmlcnf,0);
    }
    return 0;
}
static int parse_dns_sip(ddosConfig *ddosc,s_xmlcnf xmlcnf)
{
    int ret=0;
    char buff[1024];

    ret = xmlcnf_node_getattribute(xmlcnf,"random",buff);
    if(!ret)
    {
        if(!strcmp(buff,"true"))
            ddosc->style_dns.srcIpAddressRandom=1;
        else
            ddosc->style_dns.srcIpAddressRandom=0;
    }
    xmlcnf_node_next(&xmlcnf,1);
    while(xmlcnf.cur)
    {
        ret = xmlcnf_node_getvalue(xmlcnf,"value",buff);
        if(!ret)
        {
            strcpy(ddosc->style_dns.srcIpValue,buff);
            #ifdef DEBUG
            printf("sip value[%s]\n",ddosc->style_dns.srcIpValue);
            #endif
        }
        ret = xmlcnf_node_getvalue(xmlcnf,"scope",buff);
        if(!ret)
        {
            char *p=strstr(buff,",");
            int str_f_l=p-buff;
            char str_f[100];
            memcpy(str_f,buff,str_f_l);
            str_f[str_f_l]=0;

            ddosc->style_dns.srcip_s = ntohl(int_aton(str_f));
            ddosc->style_dns.srcip_e = ntohl(int_aton(p+1));
            #ifdef DEBUG
            printf("sip scope[%u][%s]-",ddosc->style_dns.srcip_s,str_f);
            printf("[%u][%s]\n",ddosc->style_dns.srcip_e,p+1);
            #endif
        }
        ret = xmlcnf_node_getvalue(xmlcnf,"meth",buff);
        if(!ret)
        {
            ddosc->style_dns.srcIpMeth = atoi(buff);
        }
        xmlcnf_node_next(&xmlcnf,0);
    }
    return 0;
}

static int parse_doc_style_dnsrf(ddosConfig *ddosc,s_xmlcnf xmlcnf)
{
    int ret=0;
    char buff[1024];

    xmlcnf_node_next(&xmlcnf,1);
    while(xmlcnf.cur)
    {
        ret = xmlcnf_node_getvalue(xmlcnf,"packetLength",buff);
        if(!ret)
        {
            ddosc->style_dns.packetLength = atoi(buff);
            #ifdef DEBUG
            printf("dns packetLength[%d]\n",ddosc->style_dns.packetLength);
            #endif
        }
        ret = xmlcnf_node_check(xmlcnf,"srcIpAddress");
        if(!ret)
        {
            parse_dns_sip(ddosc,xmlcnf);
        }
        ret = xmlcnf_node_check(xmlcnf,"srcPort");
        if(!ret)
        {
            parse_dns_sport(ddosc,xmlcnf);
        }
        ret = xmlcnf_node_check(xmlcnf,"dnsHeader");
        if(!ret)
        {
            parse_dns_header(ddosc,xmlcnf);
        }
        ret = xmlcnf_node_check(xmlcnf,"data");
        if(!ret)
        {
            parse_dns_data(ddosc,xmlcnf);
        }
        xmlcnf_node_next(&xmlcnf,0);
    }
    
    return 0;
}

static int parse_doc_styelist(ddosConfig *ddosc,s_xmlcnf xmlcnf)
{
    int ret=0;
    char buff[1024];

    xmlcnf_node_next(&xmlcnf,1);

    while(xmlcnf.cur)
    {
        ret = xmlcnf_node_check(xmlcnf,"style");
        if(!ret)
        {
            ret = xmlcnf_node_getattribute(xmlcnf,"id",buff);
            if( !strcmp(buff,"dns_requestflood") )
            {
                parse_doc_style_dnsrf(ddosc,xmlcnf);
            }
        }
        xmlcnf_node_next(&xmlcnf,0);
    }
    return 0;
}

static int parse_doc_pulse(ddosConfig *ddosc,s_xmlcnf xmlcnf)
{
    return 0;
}

static int parse_doc_packetTime(ddosConfig *ddosc,s_xmlcnf xmlcnf)
{
    int ret=0;
    char buff[1024];
    ret = xmlcnf_node_getattribute(xmlcnf,"random",buff);
    if(!ret)
    {
        if(!strcmp(buff,"true"))
            ddosc->packetTimels.packetTimeRandom=1;
        else
            ddosc->packetTimels.packetTimeRandom=0;
    }
    xmlcnf_node_next(&xmlcnf,1);
    while(xmlcnf.cur)
    {
        ret = xmlcnf_node_getvalue(xmlcnf,"value",buff);
        if(!ret)
        {
            ddosc->packetTimels.packetTimeValue = atoi(buff);
            #ifdef DEBUG
            printf("packetTime vlaue[%d]\n",ddosc->packetTimels.packetTimeValue);
            #endif
        }
        ret = xmlcnf_node_getvalue(xmlcnf,"scope",buff);
        if(!ret)
        {
            char *p=strstr(buff,",");
            int str_f_l=p-buff;
            char str_f[100];
            memcpy(str_f,buff,str_f_l);
            str_f[str_f_l]=0;
            
            ddosc->packetTimels.packetTimeScopeFrom = atoi(str_f);
            ddosc->packetTimels.packetTimeScopeTo= atoi(p+1);
            #ifdef DEBUG
            printf("packettime scope[%d]-[%d]\n",ddosc->packetTimels.packetTimeScopeFrom,ddosc->packetTimels.packetTimeScopeTo);
            #endif
        }
        ret = xmlcnf_node_getvalue(xmlcnf,"meth",buff);
        if(!ret)
        {
            ddosc->packetTimels.packetTimeMeth=atoi(buff);
            #ifdef DEBUG
            printf("packettime meth[%d]\n",ddosc->packetTimels.packetTimeMeth);
            #endif
        }
        xmlcnf_node_next(&xmlcnf,0);
    }
    return 0;
}

static int parse_doc_generalMess(ddosConfig *ddosc,s_xmlcnf xmlcnf)
{
    int ret=0;
    char buff[1024];
    ret = xmlcnf_node_getattribute(xmlcnf,"id",buff);
    if(!ret)
    {
        if( !strcmp(buff,"pulse") )
            ddosc->pulseyn=2;
        else 
            ddosc->pulseyn=1;
    }
    xmlcnf_node_next(&xmlcnf,1);
    while(xmlcnf.cur)
    {
        ret = xmlcnf_node_getvalue(xmlcnf,"startThreadNumber",buff);
        if(!ret)
        {
            ddosc->startThreadNumber = atoi(buff);
            #ifdef DEBUG
            printf("startThreadNumber[%d]\n",ddosc->startThreadNumber);
            #endif
        }
        ret = xmlcnf_node_getvalue(xmlcnf,"sendPacketNumber",buff);
        if(!ret)
        {
            ddosc->sendPacketNumber= atoi(buff);
            #ifdef DEBUG
            printf("sendPacketNumber[%d]\n",ddosc->sendPacketNumber);
            #endif
        }
        ret = xmlcnf_node_check(xmlcnf,"packetTime");
        if(!ret)
        {
            parse_doc_packetTime(ddosc,xmlcnf);
        }
        ret = xmlcnf_node_check(xmlcnf,"pulse");
        if(!ret)
        {
            parse_doc_pulse(ddosc,xmlcnf);
        }
        ret = xmlcnf_node_getvalue(xmlcnf,"attackTime",buff);
        if(!ret)
        {
            ddosc->attackTime = atoi(buff);
            #ifdef DEBUG
            printf("attackTime [%d]\n",ddosc->attackTime);
            #endif
        }
        xmlcnf_node_next(&xmlcnf,0);
    }
    return ret;
}

static int parse_doc_ddos(ddosConfig *ddosc,s_xmlcnf xmlcnf)
{
    int ret=0;
    char buff[1024];
    //循环解析同级节点
	while(xmlcnf.cur)
	{
	    ret = xmlcnf_node_getvalue(xmlcnf,"destIp",buff);
        if(!ret)
        {
            ddosc->ipls = get_ls_arr(buff);
        }
        
        ret = xmlcnf_node_getvalue(xmlcnf,"destPort",buff);
        if(!ret)
        {
            ddosc->portls = get_ls_arr(buff);
        }

        ret = xmlcnf_node_check(xmlcnf,"generalMess");
        if(!ret)
        {
            parse_doc_generalMess(ddosc,xmlcnf);
        }

        ret = xmlcnf_node_check(xmlcnf,"styleList");
        if(!ret)
        {
            parse_doc_styelist(ddosc,xmlcnf);
        }
	    xmlcnf_node_next(&xmlcnf,0);
	}
    return 0;
}


/********************************************************************************/
/* 从xml文件中得到所有属性值                                                    */
/* 输入:xml文件                                                                 */
/* return:-1 error;0 success                                                     */
/********************************************************************************/
int parse_doc_root(ddosConfig *ddosc, char *docname)
{
    if(!ddosc || !docname)
        return -1;
        
	memset(ddosc,0,sizeof(ddosConfig));
	int ret=0;
	s_xmlcnf xmlcnf;
    ret = xmlcnf_init(docname,&xmlcnf);
    if(ret)
        return ret;
	ret = xmlcnf_node_check(xmlcnf,"ddos");
	if(ret)
	{
	    xmlcnf_free(&xmlcnf);
        return ret;
    }
    char buff[1024];
	ret = xmlcnf_node_getattribute(xmlcnf,"mode",buff);
	if(ret)
	{
	    printf("[ERROR] xmlcnf attribute[mode] null\n");
	    xmlcnf_free(&xmlcnf);
	    return -1;
	}
	if( !strcmp(buff,"signal") )
	    ddosc->mode=1;
	else if( !strcmp(buff,"fixed") )
	    ddosc->mode=2;
	else
	{
	    printf("[ERROR] mode value error\n");
	    xmlcnf_free(&xmlcnf);
	    return -1;
	}
	xmlcnf_node_next(&xmlcnf,1);
	parse_doc_ddos(ddosc,xmlcnf);
    xmlcnf_free(&xmlcnf);
    return 0;
}

/********************************************************************************/
/* destroy struct ddosConfig                                                    */
/********************************************************************************/
void destroy_ddosConfig(ddosConfig *ddosc)
{
	if(ddosc){
	   
	/*
		if(ddosc->synStyle){
			free(ddosc->synStyle->tcpHeader);
			free(ddosc->synStyle->ipHeader);
			if(ddosc->synStyle->srcIpls)
				free(ddosc->synStyle->srcIpls);
			if(ddosc->synStyle->srcPortls)
				free(ddosc->synStyle->srcPortls);
			if(ddosc->synStyle->datals)
				free(ddosc->synStyle->datals);
			free(ddosc->synStyle);
			ddosc->synStyle = NULL;
		}
		if(ddosc->udpStyle){
			free(ddosc->udpStyle->udpHeader);
			free(ddosc->udpStyle->ipHeader);
			if(ddosc->udpStyle->srcIpls)
				free(ddosc->udpStyle->srcIpls);
			if(ddosc->udpStyle->srcPortls)
				free(ddosc->udpStyle->srcPortls);
			if(ddosc->udpStyle->datals)
				free(ddosc->udpStyle->datals);
			free(ddosc->udpStyle);
			ddosc->udpStyle = NULL;
		}
		if(ddosc->icmpStyle){
			free(ddosc->icmpStyle->icmpHeader);
			free(ddosc->icmpStyle->ipHeader);
			if(ddosc->icmpStyle->srcIpls)
				free(ddosc->icmpStyle->srcIpls);
			if(ddosc->icmpStyle->datals)
				free(ddosc->icmpStyle->datals);
			free(ddosc->icmpStyle);
			ddosc->icmpStyle = NULL;
		}
		if(ddosc->httpStyle){
			if(ddosc->httpStyle->datals)
				free(ddosc->httpStyle->datals);
			free(ddosc->httpStyle);
			ddosc->httpStyle = NULL;
		}
		if(ddosc->ipls)
			free(ddosc->ipls);
		if(ddosc->portls)
			free(ddosc->portls);
		destroy_packetTime(ddosc->packetTimels);
    */
		free(ddosc);
	}
}




