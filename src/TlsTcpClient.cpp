#include "TlsTcpClient.h"

TlsTcpClient::TlsTcpClient() {
  connected = false;
}

int TlsTcpClient::send_Tls(void *ctx, const unsigned char *buf, size_t len) {
  TlsTcpClient *sock = (TlsTcpClient *)ctx;

  if (!sock->client.connected()) {
    return -1;
  }

  int ret = sock->client.write(buf, len);
  if (ret == 0) {
      return MBEDTLS_ERR_SSL_WANT_WRITE;
  }
  sock->client.flush();
  return ret;
}

int TlsTcpClient::recv_Tls(void *ctx, unsigned char *buf, size_t len) {
  TlsTcpClient *sock = (TlsTcpClient *)ctx;
  // TODO: need this delay?
  delay(10);

  if (!sock->client.connected()) {
    return -1;
  }

  if (sock->client.available() == 0) {
    return MBEDTLS_ERR_SSL_WANT_READ;
  }

  int ret = sock->client.read(buf, len);
  if (ret == 0) {
    return MBEDTLS_ERR_SSL_WANT_READ;
  }
  return ret;
}

int TlsTcpClient::rng_Tls(void* handle, uint8_t* data, const size_t len_) {
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

void TlsTcpClient::debug_Tls( void *ctx, int level,
                      const char *file, int line,
                      const char *str ) {
    ((void) level);
    debug_tls("%s:%04d: %s", file, line, str);
}

time_t TlsTcpClient::particle_Time(time_t* ttime) {
  time_t nowt = Time.now();

  *ttime = nowt;
  return nowt;
}

int TlsTcpClient::veryfyCert_Tls(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
  char buf[1024];
  ((void) data);

  debug_tls("Verify requested for (Depth %d):\n", depth);
  mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "", crt);
  debug_tls("%s", buf);

  if((*flags) == 0) {
    debug_tls("  This certificate has no flags\n");
  } else {
    debug_tls(buf, sizeof(buf), "  ! ", *flags);
    debug_tls("%s\n", buf);
  }
  return 0;
}

int TlsTcpClient::init(const char *rootCaPem, const size_t rootCaPemSize) {
  return this->init(rootCaPem, rootCaPemSize, NULL, 0, NULL, 0);
}

int TlsTcpClient::init(const char *rootCaPem, const size_t rootCaPemSize,
         const char *clientCertPem, const size_t clientCertPemSize,
         const char *clientKeyPem, const size_t clientKeyPemSize) {

  int ret;
  connected = false;
  mbedtls_ssl_config_init(&conf);
  mbedtls_ssl_init(&ssl);
  mbedtls_x509_crt_init(&cacert);
  mbedtls_x509_crt_init(&clicert);
  mbedtls_pk_init(&pkey);

  mbedtls_ssl_conf_dbg(&conf, &TlsTcpClient::debug_Tls, nullptr);
  #if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_TLS_CORE_LEVEL);
  #endif

  if ((ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)rootCaPem, rootCaPemSize)) < 0) {
    debug_tls(" enableTls mbedtls_x509_crt_parse error : %d\n", ret);
    return ret;
  }

  if (clientCertPem != NULL && clientCertPemSize > 0) {
    if ((ret = mbedtls_x509_crt_parse(&clicert, (const unsigned char *)clientCertPem, clientCertPemSize)) < 0) {
      debug_tls(" tlsClientKey mbedtls_x509_crt_parse error : %d\n", ret);
      return ret;
    }
  }

  if (clientKeyPem != NULL && clientKeyPemSize > 0) {
    if ((ret = mbedtls_pk_parse_key(&pkey, (const unsigned char *)clientKeyPem, clientKeyPemSize, NULL, 0)) != 0) {
      debug_tls(" tlsClientKey mbedtls_pk_parse_key error : %d\n", ret);
      return ret;
    }
  }

  if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                 MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    return ret;
  }
  mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
  mbedtls_ssl_conf_verify(&conf, &TlsTcpClient::veryfyCert_Tls, NULL);

  // if server certificates is not valid, connection will success. check certificates on verify() function.
  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
  mbedtls_ssl_conf_rng(&conf, &TlsTcpClient::rng_Tls, nullptr);
  mbedtls_ssl_conf_ca_chain(&conf, &cacert, nullptr);

  if (clientCertPem != NULL && clientKeyPem != NULL) {
    mbedtls_ssl_conf_own_cert(&conf, &clicert, &pkey);
  }

  if((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
    return ret;
  }

  mbedtls_ssl_set_timer_cb(&ssl, &timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);
  mbedtls_ssl_set_bio(&ssl, this, &TlsTcpClient::send_Tls,  &TlsTcpClient::recv_Tls, nullptr);
  return 0;
}

void TlsTcpClient::close() {
  connected = false;
  mbedtls_x509_crt_free(&cacert);
  mbedtls_x509_crt_free(&clicert);
  mbedtls_pk_free(&pkey);
  mbedtls_ssl_config_free (&conf);
  mbedtls_ssl_free (&ssl);
  client.stop();
};


int TlsTcpClient::connect(char* domain, uint16_t port) {
  int ret;
  if (!client.connect(domain, port)) {
      debug_tls(" could not connect to server : %s\n", domain);
      return -1;
  }

  if((ret = mbedtls_ssl_set_hostname(&ssl, domain)) != 0) {
    return ret;
  }

  return this->handShake();
}

int TlsTcpClient::connect(uint8_t *ip, uint16_t port) {
  int ret;
  char buffer[16];
  sprintf(buffer, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);

  if (!client.connect(ip, port)) {
    return -1;
  }

  if((ret = mbedtls_ssl_set_hostname(&ssl, buffer)) != 0) {
    return ret;
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

  // clean ca cert/crt/pkey
  mbedtls_x509_crt_free(&cacert);
  mbedtls_x509_crt_free(&clicert);
  mbedtls_pk_free(&pkey);

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

int TlsTcpClient::read() {
  unsigned char buff[1];
  int ret = read(buff, 1);
  if (ret == 1) return buff[0];
  else    return ret;
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

int TlsTcpClient::available() {
  return client.available();
}

bool TlsTcpClient::isConnected() {
  if (client.connected())
    return connected;
  return false;
}

bool TlsTcpClient::verify() {
  int ret;
  if ((ret = mbedtls_ssl_get_verify_result(&ssl)) != 0 ) {
    char vrfy_buf[512];
    mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", ret );
    debug_tls("%s\n", vrfy_buf);
    return false;
  }
  return true;
}
