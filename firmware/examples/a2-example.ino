#include "application.h"

#include "TlsTcpClient.h"

//
// This example connect to the AWS IoT server(now testing).
//
#define AWS_ROOT_CA_PEM                                              \
"-----BEGIN CERTIFICATE-----\r\n"   \
"MIIE0zCCA7ugAwIBAgIQGNrRniZ96LtKIVjNzGs7SjANBgkqhkiG9w0BAQUFADCB\r\n"  \
"yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL\r\n"  \
"ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp\r\n"  \
"U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW\r\n"  \
"ZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0\r\n"  \
"aG9yaXR5IC0gRzUwHhcNMDYxMTA4MDAwMDAwWhcNMzYwNzE2MjM1OTU5WjCByjEL\r\n"  \
"MAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZW\r\n"  \
"ZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJpU2ln\r\n"  \
"biwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxWZXJp\r\n"  \
"U2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9y\r\n"  \
"aXR5IC0gRzUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvJAgIKXo1\r\n"  \
"nmAMqudLO07cfLw8RRy7K+D+KQL5VwijZIUVJ/XxrcgxiV0i6CqqpkKzj/i5Vbex\r\n"  \
"t0uz/o9+B1fs70PbZmIVYc9gDaTY3vjgw2IIPVQT60nKWVSFJuUrjxuf6/WhkcIz\r\n"  \
"SdhDY2pSS9KP6HBRTdGJaXvHcPaz3BJ023tdS1bTlr8Vd6Gw9KIl8q8ckmcY5fQG\r\n"  \
"BO+QueQA5N06tRn/Arr0PO7gi+s3i+z016zy9vA9r911kTMZHRxAy3QkGSGT2RT+\r\n"  \
"rCpSx4/VBEnkjWNHiDxpg8v+R70rfk/Fla4OndTRQ8Bnc+MUCH7lP59zuDMKz10/\r\n"  \
"NIeWiu5T6CUVAgMBAAGjgbIwga8wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8E\r\n"  \
"BAMCAQYwbQYIKwYBBQUHAQwEYTBfoV2gWzBZMFcwVRYJaW1hZ2UvZ2lmMCEwHzAH\r\n"  \
"BgUrDgMCGgQUj+XTGoasjY5rw8+AatRIGCx7GS4wJRYjaHR0cDovL2xvZ28udmVy\r\n"  \
"aXNpZ24uY29tL3ZzbG9nby5naWYwHQYDVR0OBBYEFH/TZafC3ey78DAJ80M5+gKv\r\n"  \
"MzEzMA0GCSqGSIb3DQEBBQUAA4IBAQCTJEowX2LP2BqYLz3q3JktvXf2pXkiOOzE\r\n"  \
"p6B4Eq1iDkVwZMXnl2YtmAl+X6/WzChl8gGqCBpH3vn5fJJaCGkgDdk+bW48DW7Y\r\n"  \
"5gaRQBi5+MHt39tBquCWIMnNZBU4gcmU7qKEKQsTb47bDN0lAtukixlE0kF6BWlK\r\n"  \
"WE9gyn6CagsCqiUXObXbf+eEZSqVir2G3l6BFoMtEMze/aiCKm0oHw0LxOXnGiYZ\r\n"  \
"4fQRbxC1lfznQgUy286dUV4otp6F01vvpX1FQHKOtw5rDgb7MzVIcbidJ4vEZV8N\r\n"  \
"hnacRHr2lVz2XTIIM6RUthg/aFzyQkqFOFSDX9HoLPKsEdao7WNq\r\n"  \
"-----END CERTIFICATE-----\r\n"
const char awsRootCApem[] = AWS_ROOT_CA_PEM;


#define AWS_CLIENT_PKEY_PEM                                              \
"-----BEGIN RSA PRIVATE KEY-----\r\n"  \
"M*IIEowIBAAKCAQEAH8iJS9wcjb3UmoJG5/rEnO1aJ4PEq9VEgYW8oUdQNOmt4+\r\n"  \
"s*aMcc22CWlQ2yLrBStJi+/Buk7axNHZ2/IsFyhAit2QmdmAUu+POtN1xG/A7h4\r\n"  \
"3c4**FvnUAdJHrhEUOtCHwpfrQt7dEqnTyZ0lRODBSkctxwHZbwtx8DSYKLRkjq\r\n"  \
"S3t+fQLGyJJe2m4oWa77HjCP2KO0DyNKi4hn4sAYMI5*Oqtb44pbcmnFmK85uX3\r\n"  \
"g9T7clDThuAvYEwjHUcpFS6cMGy4+0k6vJXSrenKH2X*n+0+wSLikRe7F5QJF82\r\n"  \
"x0/ncnC+Apv+7EdQFLqjQFCCHF2XR/2KWe+DQp:oiABAoIBAGhqVkREudWK1cZc\r\n"  \
"uZJJ/xyC4WHjW7tFzaeemupYqA70ZeHzPCSlIbotW+Mt2HqAqUSIL1sbdm01GkV\r\n"  \
"r12Bm6ZF6VtmCLkHeCo2Tmw7l4a23G2iB+LsPvmFQjioBea49pNxqQjnJYtMZtO\r\n"  \
"sNqathUVMqjsKcGOp3cGupZMkG4FWlgW59iovyFWr1FXpB3M71+PWts8xtsXf0E\r\n"  \
"jvZG7zNg+U1WAY81dxSk4TNHij5EizVfAu88liMgExOUbmnTl3KQkPWrplBTWfE\r\n"  \
"bttiVJXTTlaKdzsEOGnNhvMf6xfUvlhA0nbVTwjiU0jT+T88G1wWGZjeivIc0sE\r\n"  \
"fVdesTECgYEA5UQ5jTZztxHJCBleFdqe9LO2eZ0l5jImXKTSUFDozacYY7llEJe\r\n"  \
"E+EZaA4CXmTQwdrrZfewwwAxW0dXMOnjH8I8INRRgkH4gul76OR+MniRWiV+T+H\r\n"  \
"Y+XwqpHEEZb9PPd1bth9lXLiPAp4J31I87A+ZV4ndsFm5p9sJvHsTcCgYEAoVh2\r\n"  \
"6+T7rPOh8BJyhoqMVDpI18oVwb109s0tuSNM+Tc7tCtRISsEM5OGFqpXMAIo99R\r\n"  \
"yndGEwv6Dg1NxVJq2p/BYK1ZKaAOIGCZGdYJHb+aiHCuNb90/bVwi+BTD7RoY1m\r\n"  \
"PWDb6gSUt4wEfo8uNqR8Deiau/qHLhh/Ausl0C+gYAy0OJpKW+1eAGj3ZO7Ys5d\r\n"  \
"4BuAuT/RNKYRzOF0dDGtk4HaMtL2Cmy1fURnaj8X+iL3zgZxLUtSjWi6D6tYak1\r\n"  \
"yxccqB6VhV7n7WkEK8qI6UxTL0oe4iaE7ln5VzyKG+sp7SxwcH+1ZlBUBddiX+B\r\n"  \
"75VGjpjDdE5T5PRC9RWFQKBEwqkOgHNdGpBnK+5m+b6ifBvi1ejJFtGu+HpR3dX\r\n"  \
"aXhUgp+Sj1kb+MIc2RNuKSmJgpWMCxeJgxzyPW9Pgt6nsp1l4UocVNoA5+LE8KM\r\n"  \
"pTijYms1yNCt+XWIkkA7YNR30qyj6NGCErLIq2LQcvlF7Hx6vb1rIwp8e45XVJp\r\n"  \
"BgJZAoGBAJ0/+vaOSLwPjES6hVkgo6Q3MjW4Lp3PS2SqOFvvipdnd1INIOi4Vnt\r\n"  \
"WRoJbvrJL54D7+C4O4h6KS6c7dpkvtkszQxl+hGD5DVM7r5Ynn33Evd7vtYQ8lc\r\n"  \
"L5/lVnqmFfmkl5FlpbRzxOM+67lMHnwG4A3y+5Xgl6nt1nXbo3v\r\n"  \
"-----END RSA PRIVATE KEY-----\r\n"
const char awsPrivateKeypem[] = AWS_CLIENT_PKEY_PEM;

#define AWS_CLIENT_CERT_PEM                                              \
"-----BEGIN CERTIFICATE-----\r\n"  \
"MIIDWjCCAkKgAwIBAlIVAIojgrOQqvmDBub4AhWx8fMCOo1oMA0GCSqGSIb3DQEB\r\n"  \
"CwU23E0xSzBJBgNVBsilMQFtYXpvbiBXZWIgU2VydmljZXMgTz1BbWF6b24uY29t\r\n"  \
"IEluYy4gTD1TZWF0dGxlIFNUPVdhc2hpbmd0b24gQz1VUzAeFw0xNjEyMDgwOTAz\r\n"  \
"MjdaFw00OTEyMzEylkU5NTla3034HDAaBgNVBAMME0FXUyBJb1QgQ2VydGlmaWNh\r\n"  \
"dGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggoOAoIBAQCQfyIlL3C9yNvdSagk\r\n"  \
"bn+sSc7Vong8Sr1USBhbyls1A06a3j6xoxxzbYJaVDbIusHBK0mL78Hu6TtrE0dn\r\n"  \
"b8iwXKECK3ZCZ2YBS748603XEb8DuHjdzj4W+dQB0keuERQw60IfCl82tC3t0Sqd\r\n"  \
"PJnSVE4MFKRy3HAdlvC3HwNJgotGSOpLe359AsbIkl7abihZFrvseMIw/Yo7QPI0\r\n"  \
"qLiGfiwBgwjk6q1vjiltyacWYrzm5feD1PtyUNOLAC9gTCMctRykVLqhwwbLj7ST\r\n"  \
"q8ldKt6cofZef7T7BIu99F7sXlAkXzbHTIYycL4Cm/7sR1AXQuqNAUIkIcXZdH/Y\r\n"  \
"pZ77AgMBAAGjYDBeMB8G88UdIwQYMBaAFOFIRr2gWMoWGPYf084T62+pMO3KMB0G\r\n"  \
"A1UdDgQWBBTG5R/qcbrjDA66k/hVtHvMb8+VazAMBgNVHRMBAf8EAjAAMA4GA1Ud\r\n"  \
"DwEB/wQEAwIHg55NBgkqhkiG9w0BAQsFAAOCAQEAVBLWG4NeTSrn2PshnoWZ/LTa\r\n"  \
"L5Y+nBLX8tFXji0Ui44FGG4BsVbn3ORJG2IXsXywz2Bp888Letm1MMmrL/I5X3SG\r\n"  \
"h/wkSXYnrOcijDrX9AxU+555Ulk1XwplSvpBEyAWo1gVcwSPl0A5u19twwSKNgsi\r\n"  \
"F5zABdTa8FiY9vnuxGrWdR1mf9cTw8300wdBxXumbP16kNMeJEMsj5qw0zJfgAB7\r\n"  \
"belgyDZNgirVxnzTRp8B6uYVswsd8qkvD72303kJFb7+htGYj925Z0YGkr6xInCM\r\n"  \
"AhKHSVdXUGk6E/pIZYUoX0VkNd1234055kUMHG6V20hkkGAQ3UDAYQkmDtV1og==\r\n"  \
"-----END CERTIFICATE-----\r\n"
const char awsCertKeypem[] = AWS_CLIENT_CERT_PEM;

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
    TlsTcpClient client;

    // setup Root CA pem, cert key, client private key.
    client.init(awsRootCApem, sizeof(awsRootCApem),
                awsCertKeypem, sizeof(awsCertKeypem),
                awsPrivateKeypem, sizeof(awsPrivateKeypem));

    // connect AWS IoT server.
    client.connect("test.iot.us-east-1.amazonaws.com", 8883);

    // just wait.
    delay(10000);

    client.close();
}
