#ifndef _XMLCTR_H_
#define _XMLCTR_H_

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#define MAX_DESTIP_NUM    50          //允许配置攻击目的列表最多数目
#define MAX_DESTPORT_NUM  100         //允许配置攻击目的端口最多数目
#define MAX_PTHREAD_NUM   8           //允许配置开启的最大线程数

#define STR_BUF_LEN 1024
typedef struct _s_xmlcnf_
{
    char cnfname[STR_BUF_LEN];
    xmlDocPtr doc;
	xmlNodePtr cur;
	
}s_xmlcnf;



typedef struct _s_xmlcnf_node_
{
    char name[32];
    char value[1024];
    char att_name[32];
    char att_value[1024];
    char type;//00000001/00000010(node/attribute)
}s_xmlcnf_node;


/*
 * init xmlcnf
 * return:
 *         -1 fail
 *         0  success
 */
int xmlcnf_init(char *cnfname,s_xmlcnf *xmlcnf);

/*
 * 跳转到下一节点/子节点
 * params:
 *        nodelevel 节点层级 (0/1 同级节点/子级节点)
 */
void xmlcnf_node_next(s_xmlcnf *xmlcnf,char nodelevel);

/*
 * 释放资源
 *
 */
int xmlcnf_free(s_xmlcnf *xmlcnf);

/*
 * 比较xmlChar字符串与char字符串
 * return:
 *        0  equal
 *        ~0 different
 */
int xmlcnf_strcmp(xmlChar *strx,char *str);

/*
 * 检查当前节点名称是否为需要的
 * return:
 *        0    equal
 *        ~0   different
 */
int xmlcnf_node_check(s_xmlcnf xmlcnf,char *node_name);

/*
 * 获取当前节点属性值,存放到参数buff中
 * return:
 *         0  success
 *         ~0 fail
 */
int xmlcnf_node_getattribute(s_xmlcnf xmlcnf,char *attributename,char *buff);

/*
 * 获取当前节点值,存放到参数buff中
 * return:
 *         0  success
 *         ~0 fail
 */
int xmlcnf_node_getvalue(s_xmlcnf xmlcnf,char *nodename,char *buff);

#endif

