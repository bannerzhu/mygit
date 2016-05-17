#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <time.h>

#include "packetdns.h"

#define DNS_HEAD_LENGTH sizeof(struct _dnshdr)
#define DNS_Q_LENGTH sizeof(struct _dns_query_s)
#define DNS_RR_LENGTH sizeof(struct _rr_info)

/********************************************************************************/
/* check校验和                                                                  */
/********************************************************************************/
unsigned short checksum(unsigned short * data,unsigned short length)
{
    unsigned long sum=0;
    while (length > 1){
        sum += *data++;
        length -= sizeof(unsigned short);
    }
    if (length){
        sum += *(unsigned char *)data;
    }  
    sum = (sum >>16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

//16进制方式输出
void print_hex(unsigned char *str,int size)
{
	int index=0;
	while(index<size){
		printf("%02x ",str[index]);
		index++;
		if(index%16==0)
			printf("\n");
	}
	printf("\n");
}

//输出dns head信息
void print_dnsh(unsigned char *str)
{
	s_dnshdr * dns_header2;
	dns_header2 = (s_dnshdr *)str;
	printf("dns_header2->dns_id:%d\n",dns_header2->dns_id);
	
	printf("dns_header2->dns_qr:%d\n",dns_header2->dns_qr);
	printf("dns_header2->dns_opcode:%d\n",dns_header2->dns_opcode);
	printf("dns_header2->dns_AA:%d\n",dns_header2->dns_AA);
	printf("dns_header2->dns_TC:%d\n",dns_header2->dns_TC);
	printf("dns_header2->dns_rd:%d\n",dns_header2->dns_rd);
	printf("dns_header2->dns_ra:%d\n",dns_header2->dns_ra);
	printf("dns_header2->dns_zero:%d\n",dns_header2->dns_zero);
	printf("dns_header2->dns_rcode:%d\n",dns_header2->dns_rcode);

	printf("dns_header2->dns_num_q:%d\n",dns_header2->dns_num_q);
	printf("dns_header2->dns_num_ans:%d\n",dns_header2->dns_num_ans);
	printf("dns_header2->dns_num_auth:%d\n",dns_header2->dns_num_auth);
	printf("dns_header2->dns_num_add:%d\n",dns_header2->dns_num_add);
}
//输出dns 回应包中的问题部分的信息
void print_dns_rsp_que(unsigned char *str)
{
	unsigned char *p=str;
	int i,len;
	printf("q_name:");
	while(*p!=0){
		i=0;
		len=(int)*p;
		p++;
		while(i<len){
			printf("%c",*p);
			p++;i++;
		}
		printf(".");
	}
	printf(";");
	p++;
	s_dns_query *dns_query2;
	dns_query2 = (s_dns_query *)p;
	printf("q_type:%d;",dns_query2->q_type);
	printf("q_class:%d\n",dns_query2->q_class);
}
//输出dns回应包中的回答部分的信息
void print_dns_rsp_rr(unsigned char *str)
{
	//printf("%x %x",*str,*(str+1));
	str+=2;
	s_rr_info *rr2;
	rr2 = (s_rr_info *)str;

	printf("r_type:%d\n",rr2->type);
	printf("r_class:%d\n",rr2->rr_class);
	printf("r_ttl:%d\n",rr2->ttl);
	printf("r_rdlength:%d\n",rr2->rdlength);
	//printf("r_ip:%d\n",rr2->rdata_ip);
	
	struct in_addr *rr_ip2;
	rr_ip2 = (struct in_addr *)(str+DNS_RR_LENGTH-2);
	printf("%s\n",inet_ntoa(*rr_ip2));
	
}

//将domain字符格式化为dns包中格式并填充
//返回格式化后的长度
static 
int build_dns_domain(char * pkg_hand,char *d_name)
{
	char *p_domain,*q_domain;
	int i=0,j=0;
	q_domain=p_domain=pkg_hand;
	//*p_domain = 0;
	p_domain++;
	while(d_name[i]!='\0')
	{
		if(d_name[i]=='.')
		{
			*q_domain = j;//填充1字节
			q_domain = p_domain;
			j=0;
		}
		else
		{
			*p_domain = d_name[i];
			j++;
		}
		i++;
		p_domain++;
	}
	*q_domain = j;
	*p_domain=0;
	return i+2;
}

/* structure of Query Reply (RFC 1035 4.1.1):
 *
 *  +---------------------+
 *  |        Header       |
 *  +---------------------+
 *  |       Question      | the question for the name server
 *  +---------------------+
 *  |        Answer       | RRs answering the question
 *  +---------------------+
 *  |      Authority      | RRs pointing toward an authority
 *  +---------------------+
 *  |      Additional     | RRs holding additional information
 *  +---------------------+
 */
 /* Header section format (as modified by RFC 2535 6.1):
 *                                  1  1  1  1  1  1
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                      ID                       |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    QDCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    ANCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    NSCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    ARCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
static 
void bulid_dns_h(char *pkg_dns,unsigned short dnsid,int q_or_a,char opcode,char rd)
{
	s_dnshdr * dns_header;
	dns_header = (s_dnshdr *)pkg_dns;
	dns_header->dns_id=htons(dnsid);
	dns_header->dns_qr=q_or_a;
	dns_header->dns_opcode=opcode;
    dns_header->dns_AA=0;
    dns_header->dns_TC=0;
    dns_header->dns_rd=rd;
	dns_header->dns_ra=0;
	dns_header->dns_zero=0;
	
	dns_header->dns_num_q=htons(1);
	dns_header->dns_num_auth=0;
	dns_header->dns_num_add=0;
	dns_header->dns_num_ans=0;
	
	//print_dnsh(pkg_dns);
	//print_hex((unsigned char*)pkg_dns,DNS_HEAD_LENGTH);
}

 /* non-variable part of 4.1.2 Question Section entry:
 *                                 1  1  1  1  1  1
 *   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                                               |
 * /                     QNAME                     /
 * /                                               /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     QTYPE                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     QCLASS                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
//return Question Length
static 
int build_zone_qst(char *pkt_zone_qst,char *d_name,unsigned short qtype)
{
	s_dns_query *dns_query;
	int domain_len;
	domain_len = build_dns_domain(pkt_zone_qst,d_name);
	pkt_zone_qst = pkt_zone_qst+domain_len;
	dns_query = (s_dns_query *)pkt_zone_qst;
	dns_query->q_type = htons(qtype);
	dns_query->q_class = htons(1);
	//print_dns_rsp_que(pkg_hand);
	//print_hex((unsigned char*)pkg_hand,domain_len+DNS_Q_LENGTH);
	return domain_len+DNS_Q_LENGTH;
}


int dns_get_name(char *buf,int len_min,int len_max)
{
    int i,num;
	char s[]="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	
    int str_len = getRandomNumberFT(len_min,len_max);

    //printf("domain***[%d]\n",str_len);
    
    for(i=0;i<str_len;i++)
	{
		num = 0+(int)(62.0*rand()/(RAND_MAX+1.0));
		buf[i]=s[num];
	}
	buf[str_len]=0;
	//printf("domain***[%s]\n",buf);
	return str_len;
	
}

static int dns_get_domain(char *buf,char *name,char level,int min,int max)
{
    if(!level || level>5) //map.baidu.com.cn
    {
        strcpy(buf,name);
        #ifdef DEBUG_PRINTF_DOMAIN
        printf("req_domain : %s\n",buf);
        #endif
        return 0;
    }
    int i,p_l,total_l=0;
    char *p;
    p = buf;
    for(i=0;i<level;i++)
    {
        p_l = dns_get_name(p,min,max);
        p += p_l;
        buf[total_l+p_l]='.';
        p++;

        total_l += p_l+1;
    }
    buf[total_l]=0;
    
    strcat(buf,name);
    #ifdef DEBUG_PRINTF_DOMAIN
    printf("req_domain : %s\n",buf);
    #endif
    return total_l;
}

/*
 * set package of dns response to dnspkt
 * parameters: 
 *        dnspkt  (result:pkt of dns response)
 *        domain  (domain's name)
 *        vaule   (ip,string,null;if null,rcode=0)
 *        rrtype  (A/CANME/MX)
 *        dnsorsec(dns or dnssec)
 * return dnspkt size:
 *       >0 success
 *       -1 fail
 */
int pkt_dns_req(char *dnspkt,s_style_dns *style_dns)
{
    if(!dnspkt || !style_dns)
        return -1;
	int zone_qst_len=0;//zone len of question
	int dnspkt_len;
    unsigned short dnsid;
	if(!style_dns->dnsid_random)//0:id要递增
	{
	    dnsid = style_dns->dnsid;
	    style_dns->dnsid++;
    }
    else//id固定
        dnsid = style_dns->dnsid_random;

    bulid_dns_h(dnspkt,dnsid,e_qr_q,style_dns->opcode,style_dns->rd);
    char domain[512];

    dns_get_domain(domain,style_dns->reqname,style_dns->reqname_level,style_dns->req_sublen_min,style_dns->req_sublen_max);
   
	zone_qst_len=build_zone_qst(dnspkt+DNS_HEAD_LENGTH,domain,style_dns->req_type);

	dnspkt_len = DNS_HEAD_LENGTH+zone_qst_len;
	return dnspkt_len;
}


/********************************************************************************/
/* 组织ip_udp_DNS包                                                                 */
/********************************************************************************/
int ip_udp_dns_package(char *dataArrary,s_style_dns *udpConTemp,char *attackipstr,char *attackportstr)
{
    char buff_dnspkt[1024];
    memset(buff_dnspkt,0,1024);
    int dnspkt_len=pkt_dns_req(buff_dnspkt,udpConTemp);

	struct iphdr * ip_header;
	struct udphdr * udp_header;
	//int packageLength = udpConTemp->packetLength;
	int packageLength = sizeof(struct iphdr)+sizeof(struct udphdr)+dnspkt_len;
	
	int dataLength = packageLength-sizeof(struct iphdr)-sizeof(struct udphdr);//填充数据长度：包长度－报文头长度
	struct psdhdr_udp psdudp_header;
	
	char dataPac[MAXLENGTH];//包内负载数据
	char udp_temp[MAXLENGTH+12];//记录udp包内数据(包括伪头,主要用来校验)
	//init
	bzero(&dataPac, MAXLENGTH);
	bzero(&udp_temp,MAXLENGTH+12);
	ip_header = (struct iphdr *)malloc(sizeof(struct iphdr));
	udp_header = (struct udphdr *)malloc(sizeof(struct udphdr));
	//set IPHedaer
	//此处设置ipheader具体字段值,需要明确各字段含义,否则将导致发送包无法收到
	ip_header->ihl=sizeof(struct iphdr)/4;//ip头长度
	ip_header->version=4;//版本号
	ip_header->tos=0;
	ip_header->tot_len = packageLength;
	ip_header->id=htons(random()); 
	ip_header->frag_off=0;
	ip_header->ttl=60;//生存时间
	ip_header->protocol=IPPROTO_UDP; 
	ip_header->check=0;
	unsigned int sip_host;
	if(udpConTemp->srcIpAddressRandom==1)
	{ //随机
		//if(udpConTemp->srcIpMeth==1) 
		{ //均匀分布
		    sip_host=getRandomNumberFT(udpConTemp->srcip_s,udpConTemp->srcip_e);
			ip_header->saddr=htonl(sip_host);//获得源ip地址
            #ifdef DEBUG
			printf("random sip [%u][%u][%s]\n",sip_host,ip_header->saddr,int_ntoa(ip_header->saddr));
			#endif
		}
	}
	else 
	{ //指定源ip地址
		ip_header->saddr=inet_addr(udpConTemp->srcIpValue);
	}
	
	ip_header->daddr = inet_addr(attackipstr);
	
	//set UDPHedaer
	if(udpConTemp->srcPortRandom==1) 
	{ //随机
		//if(udpConTemp->srcPortMeth==1) 
		{ //均匀分布
			udp_header->source=htons(getRandomNumberFT(udpConTemp->srcport_s,udpConTemp->srcport_e));//获得源ip地址
            
		}
		//else{
			////非均匀分布
		//}
	}
	else 
	{ //源端口号指定
		udp_header->source=htons(udpConTemp->srcPortValue);
	}
    //printf("sport [%d][%d]\n",udp_header->source,ntohs(udp_header->source));
	
	udp_header->dest = htons(atoi(attackportstr));
	//printf("udp_header->dest::%s\n",attackportstr);
	udp_header->len = htons(packageLength-sizeof(struct iphdr));//udp length
	udp_header->check = 0;
	//set udpDheader
	psdudp_header.saddr = ip_header->saddr;
	psdudp_header.daddr = ip_header->daddr;
	psdudp_header.mbz = 0;
	psdudp_header.ptcl = IPPROTO_UDP;
	psdudp_header.udpl = htons(packageLength-sizeof(struct iphdr));
	bcopy((char *)udp_header,(char *)&psdudp_header.udpheader,sizeof(struct udphdr));
/*    
	//set data
	int i=0;
	char * getdataTemp;
	int datatemplen;
	printf("dataRandom[%d]\n",udpConTemp->dataRandom);

	if(udpConTemp->dataRandom==1) { //数据随机
		if(udpConTemp->dataMeth==1) { //均匀分布
			bzero(dataPac,sizeof(dataPac));
			int linklen = getLinkLength_arr(udpConTemp->datals);
			while(i<dataLength){
				getdataTemp=getSomeone_arr(udpConTemp->datals,getRandomNumber(linklen));//获得随机数据
				datatemplen = strlen(getdataTemp);
				if(i+datatemplen<dataLength){
					memcpy(dataPac+i,getdataTemp,datatemplen);
					i=i+datatemplen;
				}
				else
					break;
			}
		}
		else{
			////非均匀分布
		}
	}
	else{//数据指定
		memset(dataPac,'1',sizeof(dataPac));
		memcpy(dataPac,udpConTemp->dataValue,strlen(udpConTemp->dataValue));
	}
	//printf("dataPac:%s\n",dataPac);
*/
	
	memcpy(udp_temp,&psdudp_header,sizeof(psdudp_header));
	memcpy(udp_temp+sizeof(psdudp_header),buff_dnspkt,dnspkt_len);
	//get udp checksum
	//if(udpConTemp->udpHeader->check!=0)//如果用户没有设置则认为check为0
		udp_header->check = checksum((unsigned short *) &udp_temp,sizeof(psdudp_header)+dataLength);
	//else
	//	udp_header->check =0;
	//get ip checksum
	//if(udpConTemp->ipHeader->check!=0)
	//	ip_header->check=udpConTemp->ipHeader->check;
	//else
		ip_header->check=checksum((unsigned short *)&ip_header,sizeof(struct iphdr));


	//填充数据完成组包
	memcpy(dataArrary,ip_header,sizeof(struct iphdr));
	memcpy(dataArrary+sizeof(struct iphdr),udp_header,sizeof(struct udphdr));
	//free
	if(udp_header)
		free(udp_header);
	if(ip_header)
		free(ip_header);
	if(dataLength>0)
		memcpy(dataArrary+sizeof(struct iphdr)+sizeof(struct udphdr),buff_dnspkt,dnspkt_len);

	return packageLength;
}

/********************************************************************************/
/* 组织TCP_DNS包                                                                */
/********************************************************************************/
int tcp_dns_package(char *dataArrary,s_style_dns *httpConTemp)
{
    char buff_dnspkt[1024];
    memset(buff_dnspkt,0,1024);
    int dnspkt_len=pkt_dns_req(buff_dnspkt,httpConTemp);
    
	memcpy(dataArrary,buff_dnspkt,dnspkt_len);
	
	return dnspkt_len;
}


