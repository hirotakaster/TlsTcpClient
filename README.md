# Simple TLS Client library for Particle.
This library is based [mbedTLS](https://tls.mbed.org/)  library, this can use for several TLS server. Now this library is compatible with every TLS server certificate, client certification is not supported.

This library's Cipher Suite is based AES and SHA, here is cipher suite list.
* TLS_DHE_PSK_WITH_AES_256_CBC_SHA
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
* TLS_EMPTY_RENOGOTIATION_INFO_SCSV


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
"MIIFjTCCA3WgAwIBAgIRANOxciY0IzLc9AUoUSrsnGowDQYJKoZIhvcNAQELBQAw\r\n"  \
"TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\r\n"  \
"cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTYxMDA2MTU0MzU1\r\n"  \
"WhcNMjExMDA2MTU0MzU1WjBKMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg\r\n"  \
"RW5jcnlwdDEjMCEGA1UEAxMaTGV0J3MgRW5jcnlwdCBBdXRob3JpdHkgWDMwggEi\r\n"  \
"MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCc0wzwWuUuR7dyXTeDs2hjMOrX\r\n"  \
"NSYZJeG9vjXxcJIvt7hLQQWrqZ41CFjssSrEaIcLo+N15Obzp2JxunmBYB/XkZqf\r\n"  \
"89B4Z3HIaQ6Vkc/+5pnpYDxIzH7KTXcSJJ1HG1rrueweNwAcnKx7pwXqzkrrvUHl\r\n"  \
"Npi5y/1tPJZo3yMqQpAMhnRnyH+lmrhSYRQTP2XpgofL2/oOVvaGifOFP5eGr7Dc\r\n"  \
"Gu9rDZUWfcQroGWymQQ2dYBrrErzG5BJeC+ilk8qICUpBMZ0wNAxzY8xOJUWuqgz\r\n"  \
"uEPxsR/DMH+ieTETPS02+OP88jNquTkxxa/EjQ0dZBYzqvqEKbbUC8DYfcOTAgMB\r\n"  \
"AAGjggFnMIIBYzAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADBU\r\n"  \
"BgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEBATAwMC4GCCsGAQUFBwIB\r\n"  \
"FiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQub3JnMB0GA1UdDgQWBBSo\r\n"  \
"SmpjBH3duubRObemRWXv86jsoTAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3Js\r\n"  \
"LnJvb3QteDEubGV0c2VuY3J5cHQub3JnMHIGCCsGAQUFBwEBBGYwZDAwBggrBgEF\r\n"  \
"BQcwAYYkaHR0cDovL29jc3Aucm9vdC14MS5sZXRzZW5jcnlwdC5vcmcvMDAGCCsG\r\n"  \
"AQUFBzAChiRodHRwOi8vY2VydC5yb290LXgxLmxldHNlbmNyeXB0Lm9yZy8wHwYD\r\n"  \
"VR0jBBgwFoAUebRZ5nu25eQBc4AIiMgaWPbpm24wDQYJKoZIhvcNAQELBQADggIB\r\n"  \
"ABnPdSA0LTqmRf/Q1eaM2jLonG4bQdEnqOJQ8nCqxOeTRrToEKtwT++36gTSlBGx\r\n"  \
"A/5dut82jJQ2jxN8RI8L9QFXrWi4xXnA2EqA10yjHiR6H9cj6MFiOnb5In1eWsRM\r\n"  \
"UM2v3e9tNsCAgBukPHAg1lQh07rvFKm/Bz9BCjaxorALINUfZ9DD64j2igLIxle2\r\n"  \
"DPxW8dI/F2loHMjXZjqG8RkqZUdoxtID5+90FgsGIfkMpqgRS05f4zPbCEHqCXl1\r\n"  \
"eO5HyELTgcVlLXXQDgAWnRzut1hFJeczY1tjQQno6f6s+nMydLN26WuU4s3UYvOu\r\n"  \
"OsUxRlJu7TSRHqDC3lSE5XggVkzdaPkuKGQbGpny+01/47hfXXNB7HntWNZ6N2Vw\r\n"  \
"p7G6OfY+YQrZwIaQmhrIqJZuigsrbe3W+gdn5ykE9+Ky0VgVUsfxo52mwFYs1JKY\r\n"  \
"2PGDuWx8M6DlS6qQkvHaRUo0FMd8TsSlbF0/v965qGFKhSDeQoMpYnwcmQilRh/0\r\n"  \
"ayLThlHLN81gSkJjVrPI0Y8xCVPB4twb1PFUd2fPM3sA1tJ83sZ5v8vgFv2yofKR\r\n"  \
"PB0t6JzUA81mSqM3kxl5e+IZwhYAyO0OTg3/fs8HqGTNKd9BqoUwSRBzp06JMg5b\r\n"  \
"rUCGwbCUDI0mxadJ3Bz4WxR6fyNpBK2yAinWEsikxqEt\r\n"  \
"-----END CERTIFICATE----- "
const char letencryptCaPem[] = LET_ENCRYPT_CA_PEM;

#define ONE_DAY_MILLIS (24 * 60 * 60 * 1000)
unsigned long lastSync = millis();

void setup() {
    Serial.begin(9600);

    // need a Particle time sync for X509 certificates verify.
    if (millis() - lastSync > ONE_DAY_MILLIS) {
        Particle.syncTime();
        lastSync = millis();
    }
    Serial.print(Time.timeStr());
}

void loop() {
    unsigned char buff[256];

    TlsTcpClient client;

    // setup Root CA pem.
    client.init(letencryptCaPem, sizeof(letencryptCaPem));

    // connect HTTPS server.
    client.connect("www.hirotakaster.com", 443);

    if (!client.verify()) {
      Serial.println("Server Certificates is in-valid.");
    }

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
"NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5\r\n"  \
"ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur\r\n"  \
"TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC\r\n"  \
"jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc\r\n"  \
"oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq\r\n"  \
"4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA\r\n"  \
"mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d\r\n"  \
"emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=\r\n"  \
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
