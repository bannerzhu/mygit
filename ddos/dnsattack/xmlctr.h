#ifndef _XMLCTR_H_
#define _XMLCTR_H_

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#define MAX_DESTIP_NUM    50          //�������ù���Ŀ���б������Ŀ
#define MAX_DESTPORT_NUM  100         //�������ù���Ŀ�Ķ˿������Ŀ
#define MAX_PTHREAD_NUM   8           //�������ÿ���������߳���

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
 * ��ת����һ�ڵ�/�ӽڵ�
 * params:
 *        nodelevel �ڵ�㼶 (0/1 ͬ���ڵ�/�Ӽ��ڵ�)
 */
void xmlcnf_node_next(s_xmlcnf *xmlcnf,char nodelevel);

/*
 * �ͷ���Դ
 *
 */
int xmlcnf_free(s_xmlcnf *xmlcnf);

/*
 * �Ƚ�xmlChar�ַ�����char�ַ���
 * return:
 *        0  equal
 *        ~0 different
 */
int xmlcnf_strcmp(xmlChar *strx,char *str);

/*
 * ��鵱ǰ�ڵ������Ƿ�Ϊ��Ҫ��
 * return:
 *        0    equal
 *        ~0   different
 */
int xmlcnf_node_check(s_xmlcnf xmlcnf,char *node_name);

/*
 * ��ȡ��ǰ�ڵ�����ֵ,��ŵ�����buff��
 * return:
 *         0  success
 *         ~0 fail
 */
int xmlcnf_node_getattribute(s_xmlcnf xmlcnf,char *attributename,char *buff);

/*
 * ��ȡ��ǰ�ڵ�ֵ,��ŵ�����buff��
 * return:
 *         0  success
 *         ~0 fail
 */
int xmlcnf_node_getvalue(s_xmlcnf xmlcnf,char *nodename,char *buff);

#endif

