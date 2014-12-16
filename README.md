Warning:
This project is a fork of [TinyDTLS](https://sourceforge.net/p/tinydtls/code/ci/master/tree/). 
Hence, it is better to check the original.

Moreover, to use webid with CoAP you also need to make some changes in Contiki. I plan to put those
also in near future. 

CONTENTS 

This library contains functions and structures that can help
constructing a single-threaded UDP server with DTLS support in
C99. The following components are available:

* dtls
  Basic support for DTLS with pre-shared key mode.

* tests
  The subdirectory tests contains test programs that show how each
  component is used. 

BUILDING

When using the code from the git repository at sourceforge, invoke
'autoconf' to re-create the configure script. To build for Contiki,
place tinydtls into Contiki's apps directory and call 
  ./configure --with-contiki.

To use webid call configuration with 
  ./configure --with-webid.

After configuration, invoke make to build the library and associated
test programs. To add tinydtls as Contiki application, drop it into
the apps directory and add the following line to your Makefile:

  APPS += tinydtls/aes tinydtls/sha2 tinydtls/ecc tinydtls

