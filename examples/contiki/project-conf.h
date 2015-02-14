

#ifndef __PROJECT_WEBID_DTLS_CONF_H__
#define __PROJECT_WEBID_DTLS_CONF_H__


#ifndef IEEE802154_CONF_PANID
#define IEEE802154_CONF_PANID 0xABCD
#endif

#ifndef RF_CHANNEL
#define RF_CHANNEL 26
#endif


/* Disabling RDC for demo purposes. Core updates often require more memory. */
/* For projects, optimize memory and enable RDC again. */
#undef NETSTACK_CONF_RDC
#define NETSTACK_CONF_RDC			nullrdc_driver

#undef NETSTACK_CONF_WITH_IPV6
#define NETSTACK_CONF_WITH_IPV6 	1

#undef NETSTACK_CONF_MAC
#define NETSTACK_CONF_MAC     		 csma_driver

#undef UIP_CONF_LOGGING
#define UIP_CONF_LOGGING 0

#undef UIP_DS6_CONF_PERIOD
#define UIP_DS6_CONF_PERIOD (CLOCK_SECOND)

#undef UIP_CONF_TCP
#define UIP_CONF_TCP 0

#undef NETSTACK_CONF_FRAMER
#define NETSTACK_CONF_FRAMER  framer_802154

#undef CC2520_CONF_AUTOACK
#define CC2520_CONF_AUTOACK              1

/*Scandium bundles whole package therefore, we need larger uip buffers.
 * If the messages were sent separately, the largest message size should be the target*/
#undef UIP_CONF_BUFFER_SIZE
#define UIP_CONF_BUFFER_SIZE 660

#undef QUEUEBUF_CONF_NUM
#define QUEUEBUF_CONF_NUM 8


#undef NULLRDC_CONF_802154_AUTOACK
#define NULLRDC_CONF_802154_AUTOACK      1

#undef NULLRDC_CONF_SEND_802154_ACK
#define NULLRDC_CONF_SEND_802154_ACK 1


#undef RIMESTATS_CONF_ENABLED
#define RIMESTATS_CONF_ENABLED 0

/* The below is important for wismote, otherwise
 * too may DIS messages (RPL DAG solicitation), normally it is 60
 */
#undef RPL_DIS_INTERVAL_CONF
#define RPL_DIS_INTERVAL_CONF 6000


//#define UIP_DS6_CONF_NO_STATIC_ADDRESS 1

#endif /* __PROJECT_WEBID_DTLS_CONF_H__ */
