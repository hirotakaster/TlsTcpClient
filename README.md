# Simple TLS Client library for Particle Photon.
This library is based [mbedTLS](https://tls.mbed.org/)  library, this can use for several TLS server. Now this library is compatible with every TLS server certificate, client certification is not supported.

This library's Cipher Suite is based AES and SHA, here is cipher suite list.
* TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
* TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
* TLS_DHE_PSK_WITH_AES_128_CBC_SHA
* TLS_RSA_WITH_AES_256_CBC_SHA256
* TLS_RSA_WITH_AES_256_CBC_SHA
* TLS_RSA_WITH_AES_128_GCM_SHA256
* TLS_RSA_WITH_AES_128_CBC_SHA256
* TLS_RSA_WITH_AES_128_CBC_SHA
* TLS_RSA_PSK_WITH_AES_256_CBC_SHA
* TLS_RSA_PSK_WITH_AES_128_GCM_SHA256
* TLS_RSA_PSK_WITH_AES_128_CBC_SHA256
* TLS_RSA_PSK_WITH_AES_128_CBC_SHA
* TLS_PSK_WITH_AES_256_CBC_SHA
* TLS_PSK_WITH_AES_128_GCM_SHA256
* TLS_PSK_WITH_AES_128_CBC_SHA256
* TLS_PSK_WITH_AES_128_CBC_SHA


## Example
Some sample sketches included(firmware/examples/a1-example.ino).

```C++
#include "application.h"
#include "TlsTcpClient/TlsTcpClient.h"

// 
// This example connect to the Let's Encrypt HTTPS server.
// Let's Encrypt ROOT Ca PEM file is here ( https://letsencrypt.org/certificates/ )
// If you want to use other Root CA, check your server administrator or own Root CA pem.
//
#define LET_ENCRYPT_CA_PEM                                              \
"-----BEGIN CERTIFICATE----- \r\n"                                      \
"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\r\n"  \
"-----END CERTIFICATE----- \r\n"
const char letencryptCaPem[] = LET_ENCRYPT_CA_PEM;

void setup() {
    Serial.begin(9600);
}

void loop() {
    unsigned char buff[256];

    TlsTcpClient client;

    // setup Root CA pem.
    client.init(letencryptCaPem, sizeof(letencryptCaPem));
    
    // connect HTTPS server.
    client.connect("www.hirotakaster.com", 443);
    
    // Send request to HTTPS web server.
    int len = sprintf((char *)buff, "GET /robots.txt HTTP/1.0\r\nHost: www.hirotakaster.com\r\nContent-Length: 0\r\n\r\n");
    client.write(buff, len );

    // GET HTTPS response.
    memset(buff, 0, sizeof(buff));
    while(1) {
        // check response is available.
        if (!client.available()) {
            delay(100);
        } else {
            // read renponse.
            int ret = client.read(buff, sizeof(buff) - 1);
            if (ret > 0) {
                Serial.println((char *)buff);
                break;
            }
        }
    };
    delay(5000);
}

```
