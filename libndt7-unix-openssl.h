/* This file is free software under the BSD license. See AUTHORS and
 * LICENSE for more information on the copying conditions. */
#ifndef LIBNDT7_UNIX_OPENSSL_H
#define LIBNDT7_UNIX_OPENSSL_H

/**
 * @file libndt7-unix-openssl.h
 *
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
 * You can set `-D NDT7_INSECURE` to disable TLS certs verification.
 *
 * There is a bunch of macros prefixed by `NDT7_CB` that you typically wanna
 * define before including this header, e.g. NDT7_CB_HTTP_REQUEST. Using
 * such macros, you can inject code allowing you to handle specific events
 * occurring during ndt7 subtests (e.g. a speed measurement). Each undefined
 * macro will be defined by libndt7-unix-openssl.h to do nothing.
 *
 * Including this header also includes the implementation inline unless
 * you set `-D NDT7_NO_INLINE_IMPL`.
 *
 * See the ndt7-unix-openssl.c file for further insights.
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

#ifndef NDT7_CB_NDT7_ON_APP_INFO_DOWNLOAD
/** Like NDT7_CB_NDT7_ON_APP_INFO_UPLOAD but for the download. */
#define NDT7_CB_NDT7_ON_APP_INFO_DOWNLOAD(elapsed, total) /* Nothing */
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

/** malloc failed. */
#define NDT7_ERR_MALLOC 30

/** RAND_bytes failed. */
#define NDT7_ERR_RAND_BYTES 31

/*
 * API
 */

/** Contains the settings of a ndt7 test. */
struct ndt7_settings {
  const char *hostname;       /**< Is the hostname to use. */
  const char *port;           /**< Is the port to use. */
  const char *ca_bundle_path; /**< Is the CA bundle path. */
  const char *ua;             /**< Is the User-Agent. */
};

/** Runs the download subtest with the specified settings. @return zero
 * on success, one of the NDT7_ERR_XXX error codes on failure. @note We do
 * not return any error after we successfully connect, even if we get an
 * I/O error during the download, because an error after the download has
 * started should not cause it to fail. @bug This function fails with
 * NDT7_ERR_BIO_SET_CONN_HOSTNAME when the hostname is an IPv6 address,
 * because the address won't be properly quoted. */
int ndt7_download(const struct ndt7_settings *settings);

/** Like ndt7_download, but for the upload subtest. */
int ndt7_upload(const struct ndt7_settings *settings);

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
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <openssl/bio.h>
#include <openssl/rand.h>
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

static int ndt7_response_line_is_101_(const char *s) {
  /* Note: here @p s is a zero terminated string. */
  return *s++ == 'H' && *s++ == 'T' && *s++ == 'T' && *s++ == 'P' &&
      *s++ == '/' && *s++ == '1' && *s++ == '.' && *s++ == '1' &&
      *s++ == ' ' && *s++ == '1' && *s++ == '0' && *s++ == '1' && (
        *s == ' ' || *s == '\0'
      );
}

static int
ndt7_start_(BIO *conn, const char *hostname, const char *subtest,
            const char *ua, char *base, const size_t count) {
  if (conn == NULL || hostname == NULL || subtest == NULL || ua == NULL ||
      base == NULL || count <= 0 || count > INT_MAX) {
    return NDT7_ERR_INVALID_ARGUMENT;
  }
  /* TODO(bassosimone): here we should generate a random Sec-WebSocket-Key */
  int bufsiz = NDT7_TESTABLE(snprintf)(
      base, count,
      "GET /ndt/v7/%s HTTP/1.1\r\n"
      "Host: %s\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Key: DOdm+5/Cm3WwvhfcAlhJoQ==\r\n"
      "Sec-WebSocket-Version: 13\r\n"
      "Sec-WebSocket-Protocol: net.measurementlab.ndt.v7\r\n"
      "Upgrade: websocket\r\n"
      "User-Agent: %s\r\n"
      "\r\n", subtest, hostname, ua);
  if (bufsiz < 0 || (size_t)bufsiz >= count) {
    return NDT7_ERR_SNPRINTF;
  }
  NDT7_CB_HTTP_REQUEST(base);
  int ret = NDT7_TESTABLE(ndt7_bio_writeall_)(conn, base, bufsiz);
  if (ret != 0) {
    return ret;
  }
  ret = NDT7_TESTABLE(ndt7_bio_readline_)(conn, base, (int)count);
  if (ret != 0) {
    return ret;
  }
  if (!NDT7_TESTABLE(ndt7_response_line_is_101_)(base)) {
    return NDT7_ERR_HTTP_UNHANDLED_RESPONSE_LINE;
  }
  int sec_websocket_protocol = 0;
  int sec_websocket_accept = 0;
  int upgrade = 0;
  int connection = 0;
  for (int i = 0; i < 64; ++i) {
    ret = NDT7_TESTABLE(ndt7_bio_readline_)(conn, base, (int)count);
    if (ret != 0) {
      return ret;
    }
    if (NDT7_TESTABLE(strcasecmp)(
          base, "Sec-WebSocket-Protocol: net.measurementlab.ndt.v7") == 0) {
      sec_websocket_protocol = 1;
      continue;
    }
    if (NDT7_TESTABLE(strcasecmp)(
          base, "Sec-WebSocket-Accept: Nhz+x95YebD6Uvd4nqPC2fomoUQ=") == 0) {
      sec_websocket_accept = 1;
      continue;
    }
    if (NDT7_TESTABLE(strcasecmp)(base, "Upgrade: websocket") == 0) {
      upgrade = 1;
      continue;
    }
    if (NDT7_TESTABLE(strcasecmp)(base, "Connection: Upgrade") == 0) {
      connection = 1;
      continue;
    }
    if (strlen(base) == 0) {
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

/* Maximum message size according to the spec. */
#define NDT7_MAX_MESSAGE_SIZE (1 << 24)

/* Size of the mask part of the header */
#define NDT7_WS_MASK_SIZE 4

/* The minimum header size accounts for the opcode and flags (1),
 * payload length (1), and mask (4). */
#define NDT7_WS_MIN_HEADER_SIZE 6

/* The maximum header size accounts for the opcode and flags (1),
 * payload length (1), extra length (8), and mask (4). */
#define NDT7_WS_MAX_HEADER_SIZE 14

/* Computes the size of a WebSocket frame holding count payload bytes */
static int ndt7_ws_compute_bufsiz_(size_t *count) {
  if (*count < 126) {
    *count += NDT7_WS_MIN_HEADER_SIZE;
    return 0;
  }
  if (*count <= UINT16_MAX) {
    *count += NDT7_WS_MIN_HEADER_SIZE + 2;
    return 0;
  }
  if (*count <= SIZE_MAX - NDT7_WS_MAX_HEADER_SIZE) {
    *count += NDT7_WS_MAX_HEADER_SIZE;
    return 0;
  }
  return NDT7_ERR_INVALID_ARGUMENT;
}

static int ndt7_ws_recv_frame_(
    BIO *conn, char *base, const size_t count, size_t *nbytes) {
  if (conn == NULL || base == NULL || count <= 0 || nbytes == NULL) {
    return NDT7_ERR_INVALID_ARGUMENT;
  }
  *nbytes = 0;
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
    /* Artificially restrict the length to 32 bit to avoid issues with 32 bit
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
  if (opcode == NDT7_WS_OPCODE_TEXT) {
    NDT7_CB_NDT7_BEGIN_READ_MEASUREMENT();
  }
  *nbytes = length;
  while (length > 0) {
    size_t maxread = (count < length) ? count : length;
    if (maxread > INT_MAX) {
      return NDT7_ERR_OVERFLOW; /* Cannot happen because scratch is small. */
    }
    int ret = NDT7_TESTABLE(ndt7_bio_readall_)(conn, base, (int)maxread);
    if (ret != 0) {
      return ret;
    }
    if (opcode == NDT7_WS_OPCODE_TEXT) {
      NDT7_CB_NDT7_ON_MEASUREMENT_PART(base, maxread);
    } else if (opcode == NDT7_WS_OPCODE_PING) {
      /* TODO(bassosimone): here we should handle this PING. For now
         we're just going to ignore PING messages. */
    }
    assert(length >= maxread);
    length -= maxread;
  }
  if (opcode == NDT7_WS_OPCODE_TEXT) {
    NDT7_CB_NDT7_END_READ_MEASUREMENT();
  }
  /*
   * Now deal with all the messages we don't support yet.
   */
  if (opcode == NDT7_WS_OPCODE_CONTINUE || opcode == NDT7_WS_OPCODE_PONG) {
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

static long ndt7_elapsed_millisecond_(struct timeval begin, struct timeval now) {
  return ((long)now.tv_sec - (long)begin.tv_sec) * 1000L + (
      (long)now.tv_usec - (long)begin.tv_usec) / 1000L;
}

#ifndef NDT7_GETTIMEOFDAY
/* Allows you to override the function implementing gettimeofday. You want to
 * do that (1) to use a better function or (2) for testing. */
#define NDT7_GETTIMEOFDAY gettimeofday
#endif /* NDT7_GETTIMEOFDAY */

static int ndt7_download_with_buffer_(
    const struct ndt7_settings *settings, char *base, const size_t count) {
  if (settings == NULL || base == NULL || count <= 0) {
    return NDT7_ERR_INVALID_ARGUMENT;
  }
  struct ndt7_context ctx = NDT7_TESTABLE(ndt7_connect_)(settings);
  if (ctx.err != 0) {
    BIO_free_all(ctx.conn);
    return ctx.err;
  }
  ctx.err = NDT7_TESTABLE(ndt7_start_)(
      ctx.conn, settings->hostname, "download", settings->ua, base, count);
  if (ctx.err != 0) {
    BIO_free_all(ctx.conn);
    return ctx.err;
  }
  struct timeval begin;
  if (NDT7_GETTIMEOFDAY(&begin, NULL) != 0) {
    BIO_free_all(ctx.conn);
    return NDT7_ERR_GETTIMEOFDAY;
  }
  size_t totalbytes = 0;
  size_t n = 0;
  struct timeval prev = begin;
  while ((ctx.err = NDT7_TESTABLE(ndt7_ws_recv_frame_)(
      ctx.conn, base, count, &n)) == 0) {
    if (totalbytes > SIZE_MAX - n) {
      BIO_free_all(ctx.conn);
      return NDT7_ERR_OVERFLOW;
    }
    totalbytes += n;
    struct timeval now;
    if (NDT7_GETTIMEOFDAY(&now, NULL) != 0) {
      BIO_free_all(ctx.conn);
      return NDT7_ERR_GETTIMEOFDAY;
    }
    long elapsed = ndt7_elapsed_millisecond_(begin, now);
    if (ndt7_elapsed_millisecond_(prev, now) > 250) {
      prev = now;
      NDT7_CB_NDT7_ON_APP_INFO_DOWNLOAD(elapsed, totalbytes);
    }
  }
  BIO_free_all(ctx.conn);
  return 0;  /* No failure once test has started */
}

int ndt7_download(const struct ndt7_settings *settings) {
  if (settings == NULL) {
    return NDT7_ERR_INVALID_ARGUMENT;
  }
  size_t siz = NDT7_MAX_MESSAGE_SIZE;
  int err = NDT7_TESTABLE(ndt7_ws_compute_bufsiz_)(&siz);
  if (err != 0) {
    return err;
  }
  char *base = NDT7_TESTABLE(malloc)(siz);
  if (base == NULL) {
    return NDT7_ERR_MALLOC;
  }
  int r = NDT7_TESTABLE(ndt7_download_with_buffer_)(settings, base, siz);
  free(base);
  return r;
}

static int ndt7_ws_prepare_frame_(
    unsigned char *frame, size_t count, size_t desired, size_t *framesize) {
  /* Like we did for download, limit maximum message size to 1<<32. */
  if (frame == NULL || desired > UINT32_MAX || framesize == NULL) {
    return NDT7_ERR_INVALID_ARGUMENT;
  }
  size_t required = desired;
  if (NDT7_TESTABLE(ndt7_ws_compute_bufsiz_)(&required) != 0 || required > count) {
    return NDT7_ERR_INVALID_ARGUMENT;
  }
  unsigned char mask[NDT7_WS_MASK_SIZE];
  if (NDT7_TESTABLE(RAND_bytes)(mask, NDT7_WS_MASK_SIZE) != 1) {
    return NDT7_ERR_RAND_BYTES;
  }
  size_t off = 0;
  /*
   * Header and length.
   */
  frame[off++] = (unsigned char)(NDT7_WS_OPCODE_BINARY | NDT7_WS_FIN_FLAG);
  if (desired < 126) {
    frame[off++] = (unsigned char)((desired & NDT7_WS_LEN_MASK) | NDT7_WS_MASK_FLAG);
  } else if (desired <= UINT16_MAX) {
    frame[off++] = (unsigned char)((126 & NDT7_WS_LEN_MASK) | NDT7_WS_MASK_FLAG);
    frame[off++] = (unsigned char)((desired >> 8) & 0xff);
    frame[off++] = (unsigned char)((desired) & 0xff);
  } else {
    frame[off++] = (unsigned char)((127 & NDT7_WS_LEN_MASK) | NDT7_WS_MASK_FLAG);
    frame[off++] = (unsigned char)((desired >> 56) & 0xff);
    frame[off++] = (unsigned char)((desired >> 48) & 0xff);
    frame[off++] = (unsigned char)((desired >> 40) & 0xff);
    frame[off++] = (unsigned char)((desired >> 32) & 0xff);
    frame[off++] = (unsigned char)((desired >> 24) & 0xff);
    frame[off++] = (unsigned char)((desired >> 16) & 0xff);
    frame[off++] = (unsigned char)((desired >> 8) & 0xff);
    frame[off++] = (unsigned char)((desired) & 0xff);
  }
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
  if (required < off || (required - off) > INT_MAX) {
    return NDT7_ERR_OVERFLOW;
  }
  if (NDT7_TESTABLE(RAND_bytes)(&frame[off], (int)(required - off)) != 1) {
    return NDT7_ERR_RAND_BYTES;
  }
  for (size_t i = 0; off < required; off++, i++) {
    frame[off] = (unsigned char)(frame[off] ^ mask[i % NDT7_WS_MASK_SIZE]);
  }
  *framesize = off;
  return 0;
}

static int ndt7_upload_with_buffer_(
    const struct ndt7_settings *settings, char *base, const size_t count) {
  if (settings == NULL || base == NULL || count <= 0) {
    return NDT7_ERR_INVALID_ARGUMENT;
  }
  struct ndt7_context ctx = NDT7_TESTABLE(ndt7_connect_)(settings);
  if (ctx.err != 0) {
    BIO_free_all(ctx.conn);
    return ctx.err;
  }
  ctx.err = NDT7_TESTABLE(ndt7_start_)(
      ctx.conn, settings->hostname, "upload", settings->ua, base, count);
  if (ctx.err != 0) {
    BIO_free_all(ctx.conn);
    return ctx.err;
  }
  const size_t payloadsiz = 1 << 13;
  size_t framesize = 0;
  if ((ctx.err = NDT7_TESTABLE(ndt7_ws_prepare_frame_)(
          (unsigned char *)base, count, payloadsiz, &framesize)) != 0) {
    BIO_free_all(ctx.conn);
    return ctx.err;
  }
  if (framesize > INT_MAX) {
    BIO_free_all(ctx.conn);
    return NDT7_ERR_OVERFLOW;
  }
  struct timeval begin;
  if (NDT7_GETTIMEOFDAY(&begin, NULL) != 0) {
    BIO_free_all(ctx.conn);
    return NDT7_ERR_GETTIMEOFDAY;
  }
  struct timeval prev = begin;
  size_t totalbytes = 0;
  while ((ctx.err = NDT7_TESTABLE(ndt7_bio_writeall_)(
          ctx.conn, base, (int)framesize)) == 0) {
    if (totalbytes > SIZE_MAX - framesize) {
      BIO_free_all(ctx.conn);
      return NDT7_ERR_OVERFLOW;
    }
    totalbytes += framesize;
    struct timeval now;
    if (NDT7_GETTIMEOFDAY(&now, NULL) != 0) {
      BIO_free_all(ctx.conn);
      return NDT7_ERR_GETTIMEOFDAY;
    }
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
  return 0;  /* No failure once test has started */
}

int ndt7_upload(const struct ndt7_settings *settings) {
  if (settings == NULL) {
    return NDT7_ERR_INVALID_ARGUMENT;
  }
  size_t siz = NDT7_MAX_MESSAGE_SIZE;
  int err = NDT7_TESTABLE(ndt7_ws_compute_bufsiz_)(&siz);
  if (err != 0) {
    return err;
  }
  char *base = NDT7_TESTABLE(malloc)(siz);
  if (base == NULL) {
    return NDT7_ERR_MALLOC;
  }
  int r = NDT7_TESTABLE(ndt7_upload_with_buffer_)(settings, base, siz);
  free(base);
  return r;
}

#endif /* NDT7_NO_INLINE_IMPL */
#endif /* LIBNDT7_UNIX_OPENSSL_H */
