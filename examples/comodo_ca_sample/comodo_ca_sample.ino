// This script is used to connect to an influxdb instance hosted on a EC2 machine on AWS behind ELB
// This script uses the certificate for instances hosted directly by in influxcloud (Comodo EssentialSSL SHA-2)
// This script has been succesfully tested on  Particle Photon firmware v0.6.3 and TlsTcpClient v0.2.9 (based on mbedTLS v2.6.0)
// The expected reply from the server is a 204 message without body
// !!! You have to change SERVER_NAME with your own

#include "application.h"

#include "TlsTcpClient.h"
#define COMODO_ROOT_CA_PEM                                              \
"-----BEGIN CERTIFICATE----- \r\n"                                      \
"MIIGCDCCA/CgAwIBAgIQKy5u6tl1NmwUim7bo3yMBzANBgkqhkiG9w0BAQwFADCB\r\n"   \
"hTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G\r\n"   \
"A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNV\r\n"   \
"BAMTIkNPTU9ETyBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTQwMjEy\r\n"   \
"MDAwMDAwWhcNMjkwMjExMjM1OTU5WjCBkDELMAkGA1UEBhMCR0IxGzAZBgNVBAgT\r\n"   \
"EkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMR\r\n"   \
"Q09NT0RPIENBIExpbWl0ZWQxNjA0BgNVBAMTLUNPTU9ETyBSU0EgRG9tYWluIFZh\r\n"   \
"bGlkYXRpb24gU2VjdXJlIFNlcnZlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEP\r\n"   \
"ADCCAQoCggEBAI7CAhnhoFmk6zg1jSz9AdDTScBkxwtiBUUWOqigwAwCfx3M28Sh\r\n"   \
"bXcDow+G+eMGnD4LgYqbSRutA776S9uMIO3Vzl5ljj4Nr0zCsLdFXlIvNN5IJGS0\r\n"   \
"Qa4Al/e+Z96e0HqnU4A7fK31llVvl0cKfIWLIpeNs4TgllfQcBhglo/uLQeTnaG6\r\n"   \
"ytHNe+nEKpooIZFNb5JPJaXyejXdJtxGpdCsWTWM/06RQ1A/WZMebFEh7lgUq/51\r\n"   \
"UHg+TLAchhP6a5i84DuUHoVS3AOTJBhuyydRReZw3iVDpA3hSqXttn7IzW3uLh0n\r\n"   \
"c13cRTCAquOyQQuvvUSH2rnlG51/ruWFgqUCAwEAAaOCAWUwggFhMB8GA1UdIwQY\r\n"   \
"MBaAFLuvfgI9+qbxPISOre44mOzZMjLUMB0GA1UdDgQWBBSQr2o6lFoL2JDqElZz\r\n"   \
"30O0Oija5zAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNV\r\n"   \
"HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwGwYDVR0gBBQwEjAGBgRVHSAAMAgG\r\n"   \
"BmeBDAECATBMBgNVHR8ERTBDMEGgP6A9hjtodHRwOi8vY3JsLmNvbW9kb2NhLmNv\r\n"   \
"bS9DT01PRE9SU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDBxBggrBgEFBQcB\r\n"   \
"AQRlMGMwOwYIKwYBBQUHMAKGL2h0dHA6Ly9jcnQuY29tb2RvY2EuY29tL0NPTU9E\r\n"   \
"T1JTQUFkZFRydXN0Q0EuY3J0MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21v\r\n"   \
"ZG9jYS5jb20wDQYJKoZIhvcNAQEMBQADggIBAE4rdk+SHGI2ibp3wScF9BzWRJ2p\r\n"   \
"mj6q1WZmAT7qSeaiNbz69t2Vjpk1mA42GHWx3d1Qcnyu3HeIzg/3kCDKo2cuH1Z/\r\n"   \
"e+FE6kKVxF0NAVBGFfKBiVlsit2M8RKhjTpCipj4SzR7JzsItG8kO3KdY3RYPBps\r\n"   \
"P0/HEZrIqPW1N+8QRcZs2eBelSaz662jue5/DJpmNXMyYE7l3YphLG5SEXdoltMY\r\n"   \
"dVEVABt0iN3hxzgEQyjpFv3ZBdRdRydg1vs4O2xyopT4Qhrf7W8GjEXCBgCq5Ojc\r\n"   \
"2bXhc3js9iPc0d1sjhqPpepUfJa3w/5Vjo1JXvxku88+vZbrac2/4EjxYoIQ5QxG\r\n"   \
"V/Iz2tDIY+3GH5QFlkoakdH368+PUq4NCNk+qKBR6cGHdNXJ93SrLlP7u3r7l+L4\r\n"   \
"HyaPs9Kg4DdbKDsx5Q5XLVq4rXmsXiBmGqW5prU5wfWYQ//u+aen/e7KJD2AFsQX\r\n"   \
"j4rBYKEMrltDR5FL1ZoXX/nUh8HCjLfn4g8wGTeGrODcQgPmlKidrv0PJFGUzpII\r\n"   \
"0fxQ8ANAe4hZ7Q7drNJ3gjTcBpUC2JD5Leo31Rpg0Gcg19hCC0Wvgmje3WYkN5Ap\r\n"   \
"lBlGGSW4gNfL1IYoakRwJiNiqZ+Gb7+6kHDSVneFeO/qJakXzlByjAA6quPbYzSf\r\n"   \
"+AZxAeKCINT+b72x\r\n"   \
"-----END CERTIFICATE----- "
const char comodoRootCaPem[] = COMODO_ROOT_CA_PEM;

#define SERVER_NAME "INSERT_HERE_YOUR_HOST_ADDRESS.influxcloud.net" 
#define SERVER_PORT 8086

#define ONE_DAY_MILLIS (24 * 60 * 60 * 1000)
unsigned long lastSync = millis();

void setup() {
    Serial.begin(9600);

    // need a Particle time sync for X509 certificates verify.
    if (millis() - lastSync > ONE_DAY_MILLIS) {
        Particle.syncTime();
        lastSync = millis();
    }
    Serial.println(Time.timeStr());
}

void loop() {
    unsigned char buff[256];

    TlsTcpClient client;

    // setup Root CA pem.
    client.init(comodoRootCaPem, sizeof(comodoRootCaPem));

    // connect HTTPS server.
    client.connect(SERVER_NAME,  SERVER_PORT);
    if (!client.isConnected() || !client.verify()) {
      Serial.println("Server Certificates is in-valid.");
      client.close();
      delay(10000);
      return;
    }

    // Send request to HTTPS web server.
    int len = sprintf((char *)buff, "GET /ping HTTP/1.1\r\nHost: SERVER_NAME: SERVER_PORT\r\n\r\n");
    client.write(buff, len );

    // GET HTTPS response.
    memset(buff, 0, sizeof(buff));
    while(1) {
        // read renponse.
        memset(buff, 0, sizeof(buff));
        int ret = client.read(buff, sizeof(buff) - 1);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
            delay(100);
            continue;
        } else if (ret <= 0) {
            // no more read.
            break;
        } else if (ret > 0){
            Serial.println((char *)buff);
        }
    }
    delay(10000);
}
