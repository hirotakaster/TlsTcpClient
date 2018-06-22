# Simple TLS Client library for Particle.
This library is based [mbedTLS](https://tls.mbed.org/) library version 2.7.4, this can use for several TLS server. Now this library is compatible with every TLS server certificate, client private key certification. Now supported TLS 1.0, 1.1, 1.2.

This library's Cipher Suite is based AES128/256 and SHA-1/224/256/384/512 only for application firmware size, here is cipher suite list.
* TLS_RSA_WITH_AES_[128|256]_GCM_SHA[1|256|512]
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

    // check server certificate. if verify failed, TLS connection is alive.
    if (!client.verify()) {
      Serial.println("Server Certificates is in-valid.");
    }

    // Send request to HTTPS web server.
    int len = sprintf((char *)buff, "GET / HTTP/1.0\r\nHost: www.hirotakaster.com\r\nContent-Length: 0\r\n\r\n");
    client.write(buff, len );

    // GET HTTPS response.
    memset(buff, 0, sizeof(buff));
    while(1) {
        // read renponse.
        memset(buff, 0, sizeof(buff));
        int ret = client.read(buff, sizeof(buff) - 1);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
            delay(100);
        } else if (ret <= 0) {
            break;
        } else {
            Serial.println((char *)buff);
        }
    }
    delay(10000);
}

```
