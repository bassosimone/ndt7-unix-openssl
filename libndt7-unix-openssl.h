/* This file is free software under the BSD license. See AUTHORS and
 * LICENSE for more information on the copying conditions. */
#ifndef LIBNDT7_UNIX_OPENSSL_H
#define LIBNDT7_UNIX_OPENSSL_H

/*
 * This is a very simple implementation of ndt7 that assumes you are
 * on a Unix like system and are using OpenSSL 1.0.2+. The code in here
 * assumes that the following conditions are met:
 *
 * 1. the main() is ignoring the SIGPIPE signal;
 *
 * 2. the main() has called SSL_library_init and SSL_load_error_strings;
 *
 * 3. the main() has setup an alarm() to interrupt us if we have
 *    been running for too much time.
 *
 * See the ndt7-unix-openssl.c for more insights.
 */

/*
 * Macros allowing to extend this implementation.
 */

#ifndef NDT7_TESTABLE
/** Allows to rename specific symbols for running unit tests. */
#define NDT7_TESTABLE(symbol) symbol
#endif

#ifndef NDT7_CB_HTTP_REQUEST
/** Called with the request we're sending to negotiate WebSocket. @param request
 * is a C string containing the whole request. */
#define NDT7_CB_HTTP_REQUEST(request) /* Nothing */
#endif

#ifndef NDT7_CB_HTTP_RESPONSE_HEADER
/** Called with an header of the negotiate-WebSocket response. @param header is
 * a C string containing the header that was read. */
#define NDT7_CB_HTTP_RESPONSE_HEADER(header) /* Nothing */
#endif

#ifndef NDT7_CB_NDT7_BEGIN_READ_MEASUREMENT
/** Called when we start reading a ndt7 measurement message. */
#define NDT7_CB_NDT7_BEGIN_READ_MEASUREMENT() /* Nothing */
#endif

#ifndef NDT7_CB_NDT7_ON_MEASUREMENT_PART
/** Called when we're reading part of a ndt7 measurement message. @param base
 * is the pointer to a byte array. @param size is the array size as size_t. */
#define NDT7_CB_NDT7_ON_MEASUREMENT_PART(base, size) /* Nothing */
#endif

#ifndef NDT7_CB_NDT7_END_READ_MEASUREMENT
/** Called when we stop reading a ndt7 measurement message. */
#define NDT7_CB_NDT7_END_READ_MEASUREMENT() /* Nothing */
#endif

#ifndef NDT7_CB_NDT7_ON_APP_INFO_UPLOAD
/** Called when we have application level information during the upload
 * ndt7 subtest. @param elapsed is the number of elapsed millisecond. @param
 * total is the number of bytes that have been sent so far. */
#define NDT7_CB_NDT7_ON_APP_INFO_UPLOAD(elapsed, total) /* Nothing */
#endif

#ifndef NDT7_CB_TLS_ERROR
/** Called when a TLS level error occurs. Note that the error may be
 * caused by other lower-level errors. You should inspect the OpenSSL
 * error queue in this case to find out what went wrong. @param what
 * is a C string containing the name of the operation that failed. */
#define NDT7_CB_TLS_ERROR(what) /* Nothing */
#endif

#ifndef NDT7_CB_WS_OPCODE_FIN_LENGTH
/** Logs the opcode, fin flag, and length of an incoming WebSocket
 * message. @param opcode is the opcode as an integer. @param fin is
 * zero if this is not the final frame, zero otherwise. @param length
 * is the length of this frame. */
#define NDT7_CB_WS_OPCODE_FIN_LENGTH(opcode, fin, length)
#endif

/*
 * Error codes.
 */

/** SSLv23_method failed */
#define NDT7_ERR_SSLv23_METHOD 1

/** SSL_CTX_new failed */
#define NDT7_ERR_SSL_CTX_NEW 2

/** BIO_new_ssl_connect failed. */
#define NDT7_ERR_BIO_NEW_SSL_CONNECT 3

/** BIO_set_conn_hostname failed. */
#define NDT7_ERR_BIO_SET_CONN_HOSTNAME 4

/** BIO_do_connect failed. */
#define NDT7_ERR_BIO_DO_CONNECT 5

/** BIO_do_handshake failed. */
#define NDT7_ERR_BIO_DO_HANDSHAKE 6

/** snprintf failed. */
#define NDT7_ERR_SNPRINTF 7

/** An invalid argument was passed to a function. */
#define NDT7_ERR_INVALID_ARGUMENT 8

/** BIO_write failed. */
#define NDT7_ERR_BIO_WRITE 9

/** A counter would have overflowed. */
#define NDT7_ERR_OVERFLOW 10

/** An HTTP header line was longer than the maximum that this
 * implementation is willing to handle. */
#define NDT7_ERR_IMPL_HEADER_LINE_TOO_LONG 11

/** BIO_read failed. */
#define NDT7_ERR_BIO_READ 12

/** The HTTP response line is not "101 switching protocols". */
#define NDT7_ERR_HTTP_UNHANDLED_RESPONSE_LINE 13

/** We got more HTTP headers than the maximum number that this
 * implementation is willing to handle. */
#define NDT7_ERR_IMPL_TOO_MANY_HTTP_HEADERS 14

/** A required header that we would have expected to see into a valid
 * ndt7 WebScket handshake was missing in the actual WebSocket handshake. */
#define NDT7_ERR_NDT7_MISSING_REQUIRED_HEADER 15

/* The WebSocket header reserved field is nonzero. */
#define NDT7_ERR_WS_INVALID_RESERVED_FIELD 16

/* The WebSocket opcode is not among the set of known opcodes. */
#define NDT7_ERR_WS_INVALID_OPCODE 17

/* We received a masked WebSocket message when no mask was expected. */
#define NDT7_ERR_WS_UNEXPECTED_MASK 18

/** We received a WebSocket control message longer than what is
 * described as the maximum length in the RFC. */
#define NDT7_ERR_WS_INVALID_CONTROL_MESSAGE_LENGTH 19

/** We received a WebSocket 64 bit length where the most significant
 * bit was not zero as mandated by the RFC. */
#define NDT7_ERR_WS_INVALID_LENGTH_MSB 20

/** We received a ndt7 message larger than the configured maximum
 * that this implementation is able to handle. */
#define NDT7_ERR_IMPL_MESSAGE_TOO_LARGE 21

/** The remote end closed the WebSocket connection. */
#define NDT7_ERR_WS_EOF 22

/** We received a valid WebSocket opcode that we don't know how to handle
 * in this implementation of ndt7. */
#define NDT7_ERR_IMPL_UNHANDLED_OPCODE 23

/** We received a message without the fin bit set, and we don't know
 * how to handle this message in this implementation. */
#define NDT7_ERR_IMPL_UNHANDLED_CONTINUATION 24

/** gettimeofday failed. */
#define NDT7_ERR_GETTIMEOFDAY 25

/** SSL_CTX_load_verify_locations failed. */
#define NDT7_ERR_SSL_CTX_LOAD_VERIFY_LOCATIONS 26

/** BIO_get_ssl failed. */
#define NDT7_ERR_BIO_GET_SSL 27

/** SSL_get0_param failed. */
#define NDT7_ERR_SSL_GET0_PARAM 28

/** X509_VERIFY_PARAM_set1_host failed. */
#define NDT7_ERR_X509_VERIFY_PARAM_SET1_HOST 29

/*
 * API
 */

/** Contains the settings of a ndt7 test. */
struct ndt7_settings {
  const char *hostname;       /**< Is the hostname to use. */
  const char *port;           /**< Is the port to use. */
  const char *ca_bundle_path; /**< Is the CA bundle path. */
};

struct string_result {
  char *ptr;
  size_t len;
};

/** Runs the download subtest with the specified settings. Returns zero
 * on success, one of the NDT7_ERR_XXX error codes on failure. We don't
 * return any error after we successfully connect. */
int ndt7_download(const struct ndt7_settings *settings);

/** Like ndt7_download, but for the upload subtest. */
int ndt7_upload(const struct ndt7_settings *settings);

void init_string(struct string_result *s);

size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string_result *s);

static char * extractFqdn(char str[], char tag[]);
/*
 * Implementation.
 *
 * Set this define if you don't want to inline the implementation.
 */
#ifndef NDT7_NO_INLINE_IMPL


#include <sys/time.h>

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

struct ndt7_context {
  BIO *conn;
  int  err;
};

static struct ndt7_context
ndt7_connect_(const struct ndt7_settings *settings) {
  struct ndt7_context ctx;
  memset(&ctx, 0, sizeof(ctx));
  if (settings == NULL || settings->hostname == NULL ||
      settings->port == NULL || settings->ca_bundle_path == NULL) {
    ctx.err = NDT7_ERR_INVALID_ARGUMENT;
    return ctx;
  }
  const SSL_METHOD *method = NDT7_TESTABLE(SSLv23_method)();
  if (method == NULL) {
    ctx.err = NDT7_ERR_SSLv23_METHOD;
    return ctx;
  }
  SSL_CTX *sslctx = NDT7_TESTABLE(SSL_CTX_new)(method);
  if (sslctx == NULL) {
    ctx.err = NDT7_ERR_SSL_CTX_NEW;
    return ctx;
  }

#ifndef NDT7_INSECURE
  if (NDT7_TESTABLE(SSL_CTX_load_verify_locations)(
        sslctx, settings->ca_bundle_path, NULL) != 1) {
    SSL_CTX_free(sslctx);
    ctx.err = NDT7_ERR_SSL_CTX_LOAD_VERIFY_LOCATIONS;
    return ctx;
  }
#endif
  ctx.conn = NDT7_TESTABLE(BIO_new_ssl_connect)(sslctx);
  if (ctx.conn == NULL) {
    SSL_CTX_free(sslctx);
    ctx.err = NDT7_ERR_BIO_NEW_SSL_CONNECT;
    return ctx;
  }
  SSL_CTX_free(sslctx); /* Is reference counted */
#ifndef NDT7_INSECURE
  SSL *ssl = NULL;
  if (NDT7_TESTABLE(BIO_get_ssl)(ctx.conn, &ssl) != 1) {
    ctx.err = NDT7_ERR_BIO_GET_SSL;
    return ctx;
  }
  X509_VERIFY_PARAM *param = NDT7_TESTABLE(SSL_get0_param)(ssl);
  if (param == NULL) {
    ctx.err = NDT7_ERR_SSL_GET0_PARAM;
    return ctx;
  }
  X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
  if (NDT7_TESTABLE(X509_VERIFY_PARAM_set1_host)(
        param, settings->hostname, strlen(settings->hostname)) != 1) {
    ctx.err = NDT7_ERR_X509_VERIFY_PARAM_SET1_HOST;
    return ctx;
  }
  SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
#endif
  char endpoint[128];
  int epntsiz = NDT7_TESTABLE(snprintf)(endpoint, sizeof(endpoint), "%s:%s",
                                        settings->hostname, settings->port);
  if (epntsiz < 0 || (size_t)epntsiz >= sizeof(endpoint)) {
    ctx.err = NDT7_ERR_SNPRINTF;
    return ctx;
  }
  if (NDT7_TESTABLE(BIO_set_conn_hostname)(ctx.conn, endpoint) != 1) {
    ctx.err = NDT7_ERR_BIO_SET_CONN_HOSTNAME;
    return ctx;
  }
  if (NDT7_TESTABLE(BIO_do_connect)(ctx.conn) != 1) {
    ctx.err = NDT7_ERR_BIO_DO_CONNECT;
    NDT7_CB_TLS_ERROR("BIO_do_connect");
    return ctx;
  }
  if (NDT7_TESTABLE(BIO_do_handshake)(ctx.conn) != 1) {
    ctx.err = NDT7_ERR_BIO_DO_HANDSHAKE;
    NDT7_CB_TLS_ERROR("BIO_do_handshake");
    return ctx;
  }
  return ctx;
}

static int ndt7_bio_writeall_(BIO *conn, const void *buf, int count) {
  if (conn == NULL || buf == NULL || count <= 0) {
    return NDT7_ERR_INVALID_ARGUMENT;
  }
  for (int off = 0; off < count;) {
    if ((uintptr_t)buf > UINTPTR_MAX - (uintptr_t)off) {
      return NDT7_ERR_OVERFLOW;
    }
    int ret = NDT7_TESTABLE(BIO_write)(conn, buf + (size_t)off, count - off);
    if (ret < 0) {
      NDT7_CB_TLS_ERROR("BIO_write");
      return NDT7_ERR_BIO_WRITE;
    }
    if (off > INT_MAX - ret) {
      return NDT7_ERR_OVERFLOW;
    }
    off += ret;
  }
  return 0;
}

static int ndt7_bio_readall_(BIO *conn, void *buf, int count) {
  if (conn == NULL || buf == NULL || count <= 0) {
    return NDT7_ERR_INVALID_ARGUMENT;
  }
  for (int off = 0; off < count;) {
    if ((uintptr_t)buf > UINTPTR_MAX - (uintptr_t)off) {
      return NDT7_ERR_OVERFLOW;
    }
    int ret = NDT7_TESTABLE(BIO_read)(conn, buf + (size_t)off, count - off);
    if (ret < 0) {
      NDT7_CB_TLS_ERROR("BIO_read");
      return NDT7_ERR_BIO_READ;
    }
    if (off > INT_MAX - ret) {
      return NDT7_ERR_OVERFLOW;
    }
    off += ret;
  }
  return 0;
}

static int ndt7_bio_readline_(BIO *conn, char *buf, int count) {
  if (conn == NULL || buf == NULL || count <= 0) {
    return NDT7_ERR_INVALID_ARGUMENT;
  }
  for (int off = 0; off < count;) {
    if ((uintptr_t)buf > UINTPTR_MAX - (uintptr_t)off) {
      return NDT7_ERR_OVERFLOW;
    }
    int ret = NDT7_TESTABLE(BIO_read)(conn, buf + (size_t)off, 1);
    if (ret != 1) {
      NDT7_CB_TLS_ERROR("BIO_read");
      return NDT7_ERR_BIO_READ;
    }
    if (buf[off] == '\n') {
      buf[off] = '\0';
      if (off > 0 && buf[off - 1] == '\r') {
        buf[off - 1] = '\0';
      }
      NDT7_CB_HTTP_RESPONSE_HEADER(buf);
      return 0;
    }
    if (off > INT_MAX - ret) {
      return NDT7_ERR_OVERFLOW;
    }
    off += ret;
  }
  return NDT7_ERR_IMPL_HEADER_LINE_TOO_LONG;
}

static int
ndt7_start_(BIO *conn, const char *hostname, const char *subtest) {
  if (conn == NULL || hostname == NULL || subtest == NULL) {
    return NDT7_ERR_INVALID_ARGUMENT;
  }
  char buf[2048];
  /* TODO(bassosimone): here we should generate a random Sec-WebSocket-Key */
  int bufsiz = NDT7_TESTABLE(snprintf)(
      buf, sizeof(buf),
      "GET /ndt/v7/%s HTTP/1.1\r\n"
      "Host: %s\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Key: DOdm+5/Cm3WwvhfcAlhJoQ==\r\n"
      "Sec-WebSocket-Version: 13\r\n"
      "Sec-WebSocket-Protocol: net.measurementlab.ndt.v7\r\n"
      "Upgrade: websocket\r\n"
      "\r\n", subtest, hostname);
  if (bufsiz < 0 || (size_t)bufsiz >= sizeof(buf)) {
    return NDT7_ERR_SNPRINTF;
  }
  NDT7_CB_HTTP_REQUEST(buf);
  int ret = NDT7_TESTABLE(ndt7_bio_writeall_)(conn, buf, bufsiz);
  if (ret != 0) {
    return ret;
  }
  ret = NDT7_TESTABLE(ndt7_bio_readline_)(conn, buf, sizeof(buf));
  if (ret != 0) {
    return ret;
  }
  if (NDT7_TESTABLE(strcasecmp)(buf, "HTTP/1.1 101 Switching Protocols") != 0) {
    return NDT7_ERR_HTTP_UNHANDLED_RESPONSE_LINE;
  }
  int sec_websocket_protocol = 0;
  int sec_websocket_accept = 0;
  int upgrade = 0;
  int connection = 0;
  for (int i = 0; i < 64; ++i) {
    ret = NDT7_TESTABLE(ndt7_bio_readline_)(conn, buf, sizeof(buf));
    if (ret != 0) {
      return ret;
    }
    if (NDT7_TESTABLE(strcasecmp)(
          buf, "Sec-WebSocket-Protocol: net.measurementlab.ndt.v7") == 0) {
      sec_websocket_protocol = 1;
      continue;
    }
    if (NDT7_TESTABLE(strcasecmp)(
          buf, "Sec-WebSocket-Accept: Nhz+x95YebD6Uvd4nqPC2fomoUQ=") == 0) {
      sec_websocket_accept = 1;
      continue;
    }
    if (NDT7_TESTABLE(strcasecmp)(buf, "Upgrade: websocket") == 0) {
      upgrade = 1;
      continue;
    }
    if (NDT7_TESTABLE(strcasecmp)(buf, "Connection: Upgrade") == 0) {
      connection = 1;
      continue;
    }
    if (strlen(buf) == 0) {
      return (sec_websocket_protocol && sec_websocket_accept &&
              upgrade && connection) ? 0
                                     : NDT7_ERR_NDT7_MISSING_REQUIRED_HEADER;
    }
  }
  return NDT7_ERR_IMPL_TOO_MANY_HTTP_HEADERS;
}

/* Opcodes. See <https://tools.ietf.org/html/rfc6455#section-11.8>. */
#define NDT7_WS_OPCODE_CONTINUE 0
#define NDT7_WS_OPCODE_TEXT 1
#define NDT7_WS_OPCODE_BINARY 2
#define NDT7_WS_OPCODE_CLOSE 8
#define NDT7_WS_OPCODE_PING 9
#define NDT7_WS_OPCODE_PONG 10

/* Constants useful to process the first octet of a websocket frame. For more
 * info see <https://tools.ietf.org/html/rfc6455#section-5.2>. */
#define NDT7_WS_FIN_FLAG 0x80
#define NDT7_WS_RESERVED_MASK 0x70
#define NDT7_WS_OPCODE_MASK 0x0f

/* Constants useful to process the second octet of a websocket frame. For more
 * info see <https://tools.ietf.org/html/rfc6455#section-5.2>. */
#define NDT7_WS_MASK_FLAG 0x80
#define NDT7_WS_LEN_MASK 0x7f

static int ndt7_ws_recv_frame_(BIO *conn) {
  if (conn == NULL) {
    return NDT7_ERR_INVALID_ARGUMENT;
  }
  /*
   * Read message header
   */
  unsigned int opcode = 0;
  unsigned int fin = 0;
  size_t length = 0;
  {
    unsigned char buf[2];
    int ret = NDT7_TESTABLE(ndt7_bio_readall_)(conn, buf, sizeof(buf));
    if (ret != 0) {
      return ret;
    }
    fin = (buf[0] & NDT7_WS_FIN_FLAG) != 0;
    unsigned int reserved = (buf[0] & NDT7_WS_RESERVED_MASK);
    if (reserved != 0) {
      /* They only make sense for extensions, which we don't use. So we return
       * error. See <https://tools.ietf.org/html/rfc6455#section-5.2>. */
      return NDT7_ERR_WS_INVALID_RESERVED_FIELD;
    }
    opcode = (buf[0] & NDT7_WS_OPCODE_MASK);
    if (opcode != NDT7_WS_OPCODE_CONTINUE && opcode != NDT7_WS_OPCODE_TEXT &&
        opcode != NDT7_WS_OPCODE_BINARY && opcode != NDT7_WS_OPCODE_CLOSE &&
        opcode != NDT7_WS_OPCODE_PING && opcode != NDT7_WS_OPCODE_PONG) {
      /* Invalid code. See <https://tools.ietf.org/html/rfc6455#section-5.2>. */
      return NDT7_ERR_WS_INVALID_OPCODE;
    }
    unsigned int hasmask = (buf[1] & NDT7_WS_MASK_FLAG) != 0;
    if (hasmask) {
      /* We do not expect to receive a masked frame. This is client code and
       * the RFC says that a server MUST NOT mask its frames.
       * See <https://tools.ietf.org/html/rfc6455#section-5.1>. */
      return NDT7_ERR_WS_UNEXPECTED_MASK;
    }
    length = (buf[1] & NDT7_WS_LEN_MASK);
    if ((opcode == NDT7_WS_OPCODE_CLOSE || opcode == NDT7_WS_OPCODE_PING ||
         opcode == NDT7_WS_OPCODE_PONG) && (length > 125 || fin == 0)) {
      /* Control messages MUST have a payload length of 125 bytes or less
       * and MUST NOT be fragmented (see RFC6455 Sect 5.5.). */
      return NDT7_ERR_WS_INVALID_CONTROL_MESSAGE_LENGTH;
    }
  }
  /*
   * Possibly read more bytes of the length
   */
  assert(length <= 127);
  if (length == 126) {
    unsigned char buf[2];
    int ret = NDT7_TESTABLE(ndt7_bio_readall_)(conn, buf, sizeof(buf));
    if (ret != 0) {
      return ret;
    }
    length = ((size_t)buf[0] << 8) + buf[1];
  } else if (length == 127) {
    unsigned char buf[8];
    int ret = NDT7_TESTABLE(ndt7_bio_readall_)(conn, buf, sizeof(buf));
    if (ret != 0) {
      return ret;
    }
    if ((buf[0] & 0x80) != 0) {
      /* See <https://tools.ietf.org/html/rfc6455#section-5.2>: "[...] the
       * most significant bit MUST be 0." */
      return NDT7_ERR_WS_INVALID_LENGTH_MSB;
    }
    /* Artifically restrict the length to 32 bit to avoid issues with 32 bit
     * systems. Note that this is larger than ndt7 max message size. */
    if (buf[0] != 0 || buf[1] != 0 || buf[2] != 0 || buf[3] != 0) {
      return NDT7_ERR_IMPL_MESSAGE_TOO_LARGE;
    }
    length = ((size_t)buf[4] << 24) + ((size_t)buf[5] << 16)
           + ((size_t)buf[6] << 8) + buf[7];
  }
  NDT7_CB_WS_OPCODE_FIN_LENGTH(opcode, fin, length);
  /*
   * Now read the payload of the message.
   */
  char scratch[1 << 17];
  if (opcode == NDT7_WS_OPCODE_TEXT) {
    NDT7_CB_NDT7_BEGIN_READ_MEASUREMENT();
  }
  while (length > 0) {
    size_t maxread = (sizeof(scratch) < length) ? sizeof(scratch) : length;
    if (maxread > INT_MAX) {
      return NDT7_ERR_OVERFLOW; /* Cannot happen because scratch is small. */
    }
    int ret = NDT7_TESTABLE(ndt7_bio_readall_)(conn, scratch, (int)maxread);
    if (ret != 0) {
      return ret;
    }
    if (opcode == NDT7_WS_OPCODE_TEXT) {
      NDT7_CB_NDT7_ON_MEASUREMENT_PART(scratch, maxread);
    }
    assert(length >= maxread);
    length -= maxread;
  }
  if (opcode == NDT7_WS_OPCODE_TEXT) {
    NDT7_CB_NDT7_END_READ_MEASUREMENT();
  }
  /*
   * Now deal with all the messages we don't support.
   */
  if (opcode == NDT7_WS_OPCODE_CONTINUE || opcode == NDT7_WS_OPCODE_PING ||
      opcode == NDT7_WS_OPCODE_PONG) {
    return NDT7_ERR_IMPL_UNHANDLED_OPCODE;
  }
  if (!fin) {
    return NDT7_ERR_IMPL_UNHANDLED_CONTINUATION;
  }
  /*
   * Finally deal with the CLOSE control message.
   */
  if (opcode == NDT7_WS_OPCODE_CLOSE) {
    /* TODO(bassosimone): here we should send a close message to the peer but
     * in practice, we are fine with doing nothing for now. */
    return NDT7_ERR_WS_EOF;
  }
  return 0;
}

int ndt7_download(const struct ndt7_settings *settings) {
  if (settings == NULL) {
    return NDT7_ERR_INVALID_ARGUMENT;
  }
  struct ndt7_context ctx = NDT7_TESTABLE(ndt7_connect_)(settings);
  if (ctx.err != 0) {
    BIO_free_all(ctx.conn);
    return ctx.err;
  }
  ctx.err = NDT7_TESTABLE(ndt7_start_)(
      ctx.conn, settings->hostname, "download");
  if (ctx.err != 0) {
    BIO_free_all(ctx.conn);
    return ctx.err;
  }
  while ((ctx.err = NDT7_TESTABLE(ndt7_ws_recv_frame_)(ctx.conn)) == 0) {
    /* Nothing */
  }
  BIO_free_all(ctx.conn);
  return 0;
}

/* Constants for preparing frames. */
#define NDT7_WS_PREPARED_FRAME_SIZE 1 << 13
#define NDT7_WS_MASK_SIZE 4

/* TODO(bassosimone): allow for frames larger than 1<<16. */
static int ndt7_ws_prepare_frame_(unsigned char *frame, size_t count) {
  if (count != NDT7_WS_PREPARED_FRAME_SIZE) {
    return NDT7_ERR_INVALID_ARGUMENT;
  }
  /* TODO(bassosimone): the mask should be random. */
  const unsigned char mask[NDT7_WS_MASK_SIZE] = {7, 1, 1, 7};
  size_t off = 0;
  /*
   * Header
   */
  frame[off++] = (unsigned char)(NDT7_WS_OPCODE_BINARY | NDT7_WS_FIN_FLAG);
  frame[off++] = (unsigned char)((126 & NDT7_WS_LEN_MASK) | NDT7_WS_MASK_FLAG);
  /*
   * 16-bit length. We need to subtract the 8 byte header.
   */
  frame[off++] = (unsigned char)(((count - 8) >> 8) & 0xff);
  frame[off++] = (unsigned char)((count - 8) & 0xff);
  /*
   * Mask
   */
  frame[off++] = mask[0];
  frame[off++] = mask[1];
  frame[off++] = mask[2];
  frame[off++] = mask[3];
  /*
   * Body
   */
  for (size_t i = 0; off < count; off++, i++) {
    /* TODO(bassosimone): the body should be random. */
    frame[off] = (unsigned char)('A' ^ mask[i % NDT7_WS_MASK_SIZE]);
  }
  return 0;
}

static long ndt7_elapsed_millisecond_(struct timeval begin, struct timeval now) {
  return ((long)now.tv_sec - (long)begin.tv_sec) * 1000L + (
      (long)now.tv_usec - (long)begin.tv_usec) / 1000L;
}

int ndt7_upload(const struct ndt7_settings *settings) {
  if (settings == NULL) {
    return NDT7_ERR_INVALID_ARGUMENT;
  }
  struct ndt7_context ctx = NDT7_TESTABLE(ndt7_connect_)(settings);
  if (ctx.err != 0) {
    BIO_free_all(ctx.conn);
    return ctx.err;
  }
  ctx.err = NDT7_TESTABLE(ndt7_start_)(ctx.conn, settings->hostname, "upload");
  if (ctx.err != 0) {
    BIO_free_all(ctx.conn);
    return ctx.err;
  }
  unsigned char frame[NDT7_WS_PREPARED_FRAME_SIZE];
  if ((ctx.err = NDT7_TESTABLE(ndt7_ws_prepare_frame_)(
          frame, sizeof(frame))) != 0) {
    BIO_free_all(ctx.conn);
    return ctx.err;
  }
  struct timeval begin;
  /* TODO(bassosimone): gettimeofday is not monotonic. */
  (void)gettimeofday(&begin, NULL);
  struct timeval prev = begin;
  size_t totalbytes = 0;
  while ((ctx.err = NDT7_TESTABLE(ndt7_bio_writeall_)(
          ctx.conn, frame, sizeof(frame))) == 0) {
    if (totalbytes > SIZE_MAX - sizeof(frame)) {
      BIO_free_all(ctx.conn);
      return NDT7_ERR_OVERFLOW;
    }
    totalbytes += sizeof(frame);
    struct timeval now;
    (void)gettimeofday(&now, NULL);
    long elapsed = ndt7_elapsed_millisecond_(begin, now);
    if (elapsed > 10000) {
      break;
    }
    if (ndt7_elapsed_millisecond_(prev, now) > 250) {
      prev = now;
      NDT7_CB_NDT7_ON_APP_INFO_UPLOAD(elapsed, totalbytes);
    }
  }
  BIO_free_all(ctx.conn);
  return 0;
}

void init_string(struct string_result *s) {
  s->len = 0;
  s->ptr = malloc(s->len+1);
  if (s->ptr == NULL) {
    fprintf(stderr, "malloc() failed\n");
    exit(EXIT_FAILURE);
  }
  s->ptr[0] = '\0';
}

size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string_result *s)
{
  size_t new_len = s->len + size*nmemb;
  s->ptr = realloc(s->ptr, new_len+1);
  if (s->ptr == NULL) {
    fprintf(stderr, "realloc() failed\n");
    exit(EXIT_FAILURE);
  }
  memcpy(s->ptr+s->len, ptr, size*nmemb);
  s->ptr[new_len] = '\0';
  s->len = new_len;

  return size*nmemb;
}

static char * extractFqdn(char str[], char tag[]) {
	char delim[] = " ";
	int found = 0;
	char *ptr = strtok(str, delim);

	while(ptr != NULL) {
		if (found == 1) {
			return ptr;
		}
		if (strncmp(ptr, tag, strlen(tag)) == 0) {
			found=1;
		}
		ptr = strtok(NULL, delim);
	}
  exit(1);
  /* NOTREACHED */
}

#endif /* NDT7_NO_INLINE_IMPL */
#endif /* LIBNDT7_UNIX_OPENSSL_H */