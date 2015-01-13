#include "contiki.h"
#include "contiki-net.h"
#include "contiki-lib.h"
#include "sys/process.h"

#include "erbium.h"
#include "er-coap-13-dtls.h"
#include "er-coap-13.h"
#include "er-coap-13-engine.h"


#include "tinydtls.h"
#include "debug.h"
#include "dtls.h"


#include <string.h>

#ifndef DEBUG
#define DEBUG DEBUG_PRINT
#endif
#include "net/uip-debug.h"


#if UIP_CONF_IPV6_RPL
#include "net/rpl/rpl.h"
#endif /* UIP_CONF_IPV6_RPL */

#ifdef ENABLE_POWERTRACE
#include "powertrace.h"
#endif

//#define MAX_PAYLOAD_LEN 120

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[UIP_LLIPH_LEN])

#define REST_RES_HELLO 1
#define REMOTE_PORT     UIP_HTONS(5684)
#define OWNER_NODE(ipaddr)   uip_ip6addr(ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0x0001)
static uip_ipaddr_t owner_ipaddr;


/*------------------PROCESS----------------------*/
process_event_t delegation_event;
PROCESS(coaps_server_process, "COAPS server process");
PROCESS(coaps_delegator, "COAPS authorization delegator");
AUTOSTART_PROCESSES(&coaps_server_process,&coaps_delegator);


/*------------------PROCESS----------------------*/

/*-------------------------------ECDSA---------------------------------------*/
#ifdef DTLS_ECC

static const unsigned char ecdsa_priv_key[] = {
			0xD9, 0xE2, 0x70, 0x7A, 0x72, 0xDA, 0x6A, 0x05,
			0x04, 0x99, 0x5C, 0x86, 0xED, 0xDB, 0xE3, 0xEF,
			0xC7, 0xF1, 0xCD, 0x74, 0x83, 0x8F, 0x75, 0x70,
			0xC8, 0x07, 0x2D, 0x0A, 0x76, 0x26, 0x1B, 0xD4};

static const unsigned char ecdsa_pub_key_x[] = {
			0xD0, 0x55, 0xEE, 0x14, 0x08, 0x4D, 0x6E, 0x06,
			0x15, 0x59, 0x9D, 0xB5, 0x83, 0x91, 0x3E, 0x4A,
			0x3E, 0x45, 0x26, 0xA2, 0x70, 0x4D, 0x61, 0xF2,
			0x7A, 0x4C, 0xCF, 0xBA, 0x97, 0x58, 0xEF, 0x9A};

static const unsigned char ecdsa_pub_key_y[] = {
			0xB4, 0x18, 0xB6, 0x4A, 0xFE, 0x80, 0x30, 0xDA,
			0x1D, 0xDC, 0xF4, 0xF4, 0x2E, 0x2F, 0x26, 0x31,
			0xD0, 0x43, 0xB1, 0xFB, 0x03, 0xE2, 0x2F, 0x4D,
			0x17, 0xDE, 0x43, 0xF9, 0xF9, 0xAD, 0xEE, 0x70};
#ifdef DTLS_WEBID

#ifndef WEBID_MAX_CONCURRENT_AUTHORIZATIONS
#define WEBID_MAX_CONCURRENT_AUTHORIZATIONS 2
#endif
typedef struct session_auth{
	struct session_auth *next;
	session_t session;
	char uri[DTLS_WEBID_MAX_URI_LENGTH];
	size_t uri_size;

} session_auth_t;

LIST(session_table);
MEMB(session_mem, struct session_auth, WEBID_MAX_CONCURRENT_AUTHORIZATIONS);

/*
 * For URIs shorter the better upper limit is '50' see DTLS_WEBID_MAX_URI_LENGTH.
 * the uri by default starts with https:// so omitted,
 * If another prefix/protocol is required, that protocol should be added to the uri such as coaps://example.com/...
 * */
static const unsigned char webid_uri[] = "example.com/point/to/the/resource";
#endif /* DTLS_WEBID */

#endif /* DTLS_ECC */
/*---------------------------------------------------------------------------*/

static int
send_to_peer(struct dtls_context_t *ctx,
             session_t *session, uint8 *data, size_t len);

static int
read_from_peer(struct dtls_context_t *ctx,
               session_t *session, uint8 *data, size_t len);

#ifdef DTLS_PSK
/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
static int
get_psk_info(struct dtls_context_t *ctx, const session_t *session,
	     dtls_credentials_type_t type,
	     const unsigned char *id, size_t id_len,
	     unsigned char *result, size_t result_length) {

  struct keymap_t {
    unsigned char *id;
    size_t id_length;
    unsigned char *key;
    size_t key_length;
  } psk[3] = {
    { (unsigned char *)"Client_identity", 15,
      (unsigned char *)"secretPSK", 9 },
    { (unsigned char *)"default identity", 16,
      (unsigned char *)"\x11\x22\x33", 3 },
    { (unsigned char *)"\0", 2,
      (unsigned char *)"", 1 }
  };

  if (type != DTLS_PSK_KEY) {
    return 0;
  }

  if (id) {
    int i;
    for (i = 0; i < sizeof(psk)/sizeof(struct keymap_t); i++) {
      if (id_len == psk[i].id_length && memcmp(id, psk[i].id, id_len) == 0) {
	if (result_length < psk[i].key_length) {
	  dtls_warn("buffer too small for PSK");
	  return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
	}

	memcpy(result, psk[i].key, psk[i].key_length);
	return psk[i].key_length;
      }
    }
  }

  return dtls_alert_fatal_create(DTLS_ALERT_DECRYPT_ERROR);
}
#endif /* DTLS_PSK */

#ifdef DTLS_ECC
static int
get_ecdsa_key(struct dtls_context_t *ctx,
	      const session_t *session,
	      const dtls_ecdsa_key_t **result) {
  static const dtls_ecdsa_key_t ecdsa_key = {
    .curve = DTLS_ECDH_CURVE_SECP256R1,
    .priv_key = ecdsa_priv_key,
    .pub_key_x = ecdsa_pub_key_x,
    .pub_key_y = ecdsa_pub_key_y
#ifdef DTLS_WEBID
    , .webid_uri = webid_uri
#endif
  };

  *result = &ecdsa_key;
  return 0;
}


static session_t authorization_session;
static int
verify_ecdsa_key(struct dtls_context_t *ctx,
		 const session_t *session,
		 const unsigned char *other_pub_x,
		 const unsigned char *other_pub_y,
		 size_t key_size
#ifdef DTLS_WEBID
	     , const unsigned char *webid_uri,
		 size_t webid_uri_size
#endif
		 ) {

#ifdef DTLS_WEBID

  printf("dtls-webid: In verify ecdsa the uri is -%.*s- with length:%d\n",webid_uri_size,webid_uri,webid_uri_size);

  /* FIXME: INSTEAD of URI comparison, the certificate of the server should be CHECKED!!!!*/
  if (strcmp((const char*)webid_uri,"example.org/owner_webid/") != 0 ){
	  char query[200];
	  session_auth_t *s;

	  s= memb_alloc(&session_mem);
	  if(NULL == s){
		  dtls_warn("The session table for authorizations is full. We cannot authorize %.*s\n",webid_uri_size, webid_uri);
		  return NOT_AUTHORIZED;
	  }
	  dtls_session_init(&s->session);
	  dtls_session_copy(session,&s->session);
	  s->uri_size = webid_uri_size;
	  memcpy(s->uri,webid_uri,webid_uri_size);
	  list_add(session_table,s);

	  sprintf(query,"x=%.*s&y=%.*s&uri=%.*s",key_size,(const char *)other_pub_x,key_size,(const char *)other_pub_y,webid_uri_size,(const char *)webid_uri);
	  printf("dtls-webid: delegating -%s- \n",query);
	  process_post_synch(&coaps_delegator,delegation_event, query);

	  return WAIT_AUTHORIZATION;
  }
#endif /* DTLS_WEBID */
  printf("dtls-webid: verify ecdsa this guy is safe to go -%.*s-\n",webid_uri_size,webid_uri);
  return AUTHORIZED;
}
#endif /* DTLS_ECC */

int
coap_init_communication_layer(uint16_t port)
{
	static dtls_handler_t cb = {
	    .write = send_to_peer,
	    .read  = read_from_peer,
	    .event = NULL,
	#ifdef DTLS_PSK
	    .get_psk_info = get_psk_info,
	#endif /* DTLS_PSK */
	#ifdef DTLS_ECC
	    .get_ecdsa_key = get_ecdsa_key,
	    .verify_ecdsa_key = verify_ecdsa_key
	#endif /* DTLS_ECC */
	  };

	  PRINTF("DTLS server started\n");


  struct uip_udp_conn *server_conn = udp_new(NULL, 0, NULL);
  udp_bind(server_conn, port);

  dtls_set_log_level(DTLS_LOG_DEBUG);

  coap_default_context = dtls_new_context(server_conn);
  if (coap_default_context)
    dtls_set_handler(coap_default_context, &cb);
  else
	  return -1;

  /* new connection with remote host */
  printf("COAP-DTLS listening on port %u\n", uip_ntohs(server_conn->lport));
  return 0;
}
/*-----------------------------------------------------------------------------------*/
static int
send_to_peer(struct dtls_context_t *ctx,
             session_t *session, uint8 *data, size_t len) {

  struct uip_udp_conn *conn = (struct uip_udp_conn *)dtls_get_app_data(ctx);

  uip_ipaddr_copy(&conn->ripaddr, &session->addr);
  conn->rport = session->port;

  uip_udp_packet_send(conn, data, len);

  PRINTF("send to ");
      PRINT6ADDR(&conn->ripaddr);
      PRINTF(":%u\n", uip_ntohs(conn->rport));

  /* Restore server connection to allow data from any node */
  memset(&conn->ripaddr, 0, sizeof(conn->ripaddr));
  memset(&conn->rport, 0, sizeof(conn->rport));

  return len;
}


/*-----------------------------------------------------------------------------------*/
void
coap_send_message(context_t * ctx, uip_ipaddr_t *addr, uint16_t port, uint8_t *data, uint16_t length)
{
  session_t session;

  dtls_session_init(&session);
  uip_ipaddr_copy(&session.addr, addr);
  session.port = port;

  dtls_write(ctx, &session, data, length);
}
/*-----------------------------------------------------------------------------------*/
static int
read_from_peer(struct dtls_context_t *ctx,
               session_t *session, uint8 *data, size_t len) {
  uip_len = len;
  memmove(uip_appdata, data, len);
  coap_receive(ctx);
  return 0;
}



/*-----------------------------------------------------------------------------------*/

void
coap_handle_receive()
{
  session_t session;

  if(uip_newdata()) {
    dtls_session_init(&session);
    uip_ipaddr_copy(&session.addr, &UIP_IP_BUF->srcipaddr);
    session.port = UIP_UDP_BUF->srcport;

    dtls_handle_message(coap_default_context, &session, uip_appdata, uip_datalen());
  }
}

/*---------------------------------------------------------------------------*/
static void
print_local_addresses(void)
{
  int i;
  uint8_t state;

  PRINTF("Server IPv6 addresses: \n");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      PRINTF("\n");
    }
  }
}



/******************************************************************************/
#if REST_RES_HELLO
/*
 * Resources are defined by the RESOURCE macro.
 * Signature: resource name, the RESTful methods it handles, and its URI path (omitting the leading slash).
 */
RESOURCE(helloworld, METHOD_GET, "hello", "title=\"Hello world: ?len=0..\";rt=\"Text\"");

/*
 * A handler function named [resource name]_handler must be implemented for each RESOURCE.
 * A buffer for the response payload is provided through the buffer pointer. Simple resources can ignore
 * preferred_size and offset, but must respect the REST_MAX_CHUNK_SIZE limit for the buffer.
 * If a smaller block size is requested for CoAP, the REST framework automatically splits the data.
 */
void
helloworld_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  const char *len = NULL;
  /* Some data that has the length up to REST_MAX_CHUNK_SIZE. For more, see the chunk resource. */
  char const * const message = "Hello World! ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy";
  int length = 12; /*           |<-------->| */

  /* The query string can be retrieved by rest_get_query() or parsed for its key-value pairs. */
  if (REST.get_query_variable(request, "len", &len)) {
    length = atoi(len);
    if (length<0) length = 0;
    if (length>REST_MAX_CHUNK_SIZE) length = REST_MAX_CHUNK_SIZE;
    memcpy(buffer, message, length);
  } else {
    memcpy(buffer, message, length);
  }

  REST.set_header_content_type(response, REST.type.TEXT_PLAIN); /* text/plain is the default, hence this option could be omitted. */
  REST.set_header_etag(response, (uint8_t *) &length, 1);
  REST.set_response_payload(response, buffer, length);
}
#endif
extern uint16_t current_mid;

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(coaps_server_process, ev, data)
{
  PROCESS_BEGIN();

  dtls_init();

  PRINTF("Starting CoAPS receiver...\n");


  coap_register_as_transaction_handler();
  current_mid = random_rand();
  if (coap_init_communication_layer(UIP_HTONS(5684)) < 0) {
     dtls_emerg("cannot create context\n");
     PROCESS_EXIT();
   }


  PRINTF("uIP buffer: %u\n", UIP_BUFSIZE);
    PRINTF("LL header: %u\n", UIP_LLH_LEN);
    PRINTF("IP+UDP header: %u\n", UIP_IPUDPH_LEN);
    PRINTF("REST max chunk: %u\n", REST_MAX_CHUNK_SIZE);

    /* Initialize the REST engine. */
    rest_init_engine();



    print_local_addresses();



#ifdef ENABLE_POWERTRACE
  powertrace_start(CLOCK_SECOND * 2);
#endif

  /* Activate the application-specific resources. */
  #if REST_RES_HELLO
    rest_activate_resource(&resource_helloworld);
  #endif

  while(1) {
    PROCESS_WAIT_EVENT();
    if(ev == tcpip_event) {
      coap_handle_receive();
    }else if (ev == PROCESS_EVENT_TIMER) {
        /* retransmissions are handled here */
        coap_check_transactions();
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/

#ifdef DTLS_WEBID
/* This function is will be passed to COAP_BLOCKING_REQUEST() to handle responses. */
void
client_chunk_handler(void *response)
{
  const uint8_t *chunk;
  session_auth_t *s=NULL;

  int len = coap_get_payload(response, &chunk);
  printf("dtls-webid: Waiting sessions are %d, Chunk: |%.*s|\n",list_length(session_table), len, (char *)chunk);

  for(s = list_head(session_table); s != NULL && strncmp(s->uri,((const char*)&chunk[1]),len-1) != 0; s = s->next) {}

  if(NULL == s){
	  dtls_warn("The stored session is missing. There is a problem with authorization server \n");
	  return;
  }

  if(chunk[0] == '1'){
	  authorized_finish(coap_default_context,&s->session,AUTHORIZED);
  } else {
	  authorized_finish(coap_default_context,&s->session,NOT_AUTHORIZED);
  }

  list_remove(session_table,s);
  memb_free(&session_mem,s);
  printf("dtls-webid: Waiting sessions are %d \n",list_length(session_table));
}




PROCESS_THREAD(coaps_delegator, ev, data)
{
  PROCESS_BEGIN();

  static coap_packet_t request[1]; /* This way the packet can be treated as pointer as usual. */
  OWNER_NODE(&owner_ipaddr);
  delegation_event = process_alloc_event();

  memb_init(&session_mem);
  list_init(session_table);

  printf("dtls-webid: Delegation process has started \n");


  while(1) {
	  PROCESS_WAIT_EVENT_UNTIL(ev == delegation_event);

	  // TODO: JSON format would be nicer.
      printf("dtls-webid: --Delegate-- with query -%s-\n",(char *)data);

      /* prepare request, TID is set by COAP_BLOCKING_REQUEST() */
      coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0 );
      coap_set_header_uri_path(request, "/verify");

      //coap_set_payload(request, (uint8_t *)(data+sizeof(uint8_t)), dtls_uint8_to_int(data));
      coap_set_header_uri_query(request,(const char *)data);

      PRINT6ADDR(&owner_ipaddr);
      PRINTF("dtls-webid : %u\n", REMOTE_PORT);

      COAP_BLOCKING_REQUEST(coap_default_context,&owner_ipaddr, REMOTE_PORT, request, client_chunk_handler);


      printf("\ndtls-webid:--Delegation Done--\n");

  }




  PROCESS_END();
}
#endif /* DTLS_WEBID */
