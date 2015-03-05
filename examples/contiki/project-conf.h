

#ifndef __PROJECT_WEBID_DTLS_CONF_H__
#define __PROJECT_WEBID_DTLS_CONF_H__


#undef IEEE802154_CONF_PANID
#define IEEE802154_CONF_PANID 0xABCD




/* Disabling RDC for demo purposes. Core updates often require more memory. */
/* For projects, optimize memory and enable RDC again. */
#undef NETSTACK_CONF_RDC
#define NETSTACK_CONF_RDC  nullrdc_driver

//#undef NETSTACK_CONF_RDC_CHANNEL_CHECK_RATE
//#define NETSTACK_CONF_RDC_CHANNEL_CHECK_RATE 16

#undef NETSTACK_CONF_WITH_IPV6
#define NETSTACK_CONF_WITH_IPV6 	1

#undef NETSTACK_CONF_MAC
#define NETSTACK_CONF_MAC     		 csma_driver

#undef UIP_CONF_LOGGING
#define UIP_CONF_LOGGING 0


/*Scandium bundles whole package therefore, we need larger uip buffers.
 * If the messages were sent separately, the largest message size should be the target*/
//#undef UIP_CONF_BUFFER_SIZE
//#define UIP_CONF_BUFFER_SIZE 600
//
#undef QUEUEBUF_CONF_NUM
#define QUEUEBUF_CONF_NUM 10



/* The below is important for wismote, otherwise
 * too may DIS messages (RPL DAG solicitation), normally it is 60
 */
//#undef RPL_DIS_INTERVAL_CONF
//#define RPL_DIS_INTERVAL_CONF 6000


//#define UIP_DS6_CONF_NO_STATIC_ADDRESS 1

#endif /* __PROJECT_WEBID_DTLS_CONF_H__ */
