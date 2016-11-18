#include "TlsTcpClient.h"

TlsTcpClient::TlsTcpClient() {
  connected = false;
}

int TlsTcpClient::send_Tls(void *ctx, const unsigned char *buf, size_t len) {
  TlsTcpClient *sock = (TlsTcpClient *)ctx;

  int ret = sock->client.write(buf, len);
  if (ret == 0)
      return MBEDTLS_ERR_SSL_WANT_WRITE;
  sock->client.flush();
  return ret;
}

int TlsTcpClient::recv_Tls(void *ctx, unsigned char *buf, size_t len) {
  TlsTcpClient *sock = (TlsTcpClient *)ctx;

  if (sock->client.available() == 0)
      return MBEDTLS_ERR_SSL_WANT_READ;

  int ret = sock->client.read(buf, len);
  if (ret == 0) {
      return MBEDTLS_ERR_SSL_WANT_READ;
  }
  return ret;
}

int TlsTcpClient::tls_rng(void* handle, uint8_t* data, const size_t len_) {
  size_t len = len_;
  while (len>=4) {
    *((uint32_t*)data) = HAL_RNG_GetRandomNumber();
    data += 4;
    len -= 4;
  }
  while (len-->0) {
    *data++ = HAL_RNG_GetRandomNumber();
  }
  return 0;
}

int TlsTcpClient::init(const char *rootCaPem, const size_t rootCaPemSize) {
  int ret;
  connected = false;
  mbedtls_ssl_config_init(&conf);
  mbedtls_x509_crt_init(&cacert);
  mbedtls_ssl_conf_rng(&conf, &TlsTcpClient::tls_rng, nullptr);

  if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                  MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    return ret;
  }

  if ((ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)rootCaPem, rootCaPemSize)) < 0) {
    return ret;
  }
  mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
  mbedtls_ssl_conf_ca_chain(&conf, &cacert, nullptr);
  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_init(&ssl);
  if((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
    return ret;
  }

  mbedtls_ssl_set_timer_cb(&ssl, &timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);
  mbedtls_ssl_set_bio(&ssl, this, &TlsTcpClient::send_Tls,  &TlsTcpClient::recv_Tls, nullptr);
  return 0;
}

void TlsTcpClient::close() {
  connected = false;
  mbedtls_x509_crt_free (&cacert);
  mbedtls_ssl_config_free (&conf);
  mbedtls_ssl_free (&ssl);
  client.stop();
};


int TlsTcpClient::connect(char* domain, uint16_t port) {
  if (!client.connect(domain, port)) {
      return -1;
  }
  return this->handShake();
}

int TlsTcpClient::connect(uint8_t *ip, uint16_t port) {
  if (!client.connect(ip, port)) {
    return -1;
  }
  return this->handShake();
}

int TlsTcpClient::handShake() {
  int ret;
  do {
      while (ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
          ret = mbedtls_ssl_handshake_client_step(&ssl);
          if (ret != 0)
              break;
      }
  } while(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  if (ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
    connected = true;
    return 0;
  }
  return ret;
}

int TlsTcpClient::write(unsigned char *buff, int length) {
  if (connected) {
      int ret = mbedtls_ssl_write( &ssl, buff, length );
      return ret;
  } else
    return -1;
}

int TlsTcpClient::read(unsigned char *buff, int length) {
  if (connected) {
      int ret = mbedtls_ssl_read(&ssl, buff, length);
      if (ret < 0) {
            switch (ret) {
            case MBEDTLS_ERR_SSL_WANT_READ:
                break;
            case MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE:
                ret = 0;
                break;
            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
            default:
                close();
                return -1;
          }
      }
      return ret;
  } else
    return -1;
}
