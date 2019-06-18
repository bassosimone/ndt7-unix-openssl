#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

#include <openssl/err.h>

/*
 * Macros that modify libndt-unix-openssl.h behaviour.
 */

#ifdef NDT7_PRINT_HEADER
/* This is the callback called when we're about to send the HTTP request
 * for upgrading the connection to WebSocket. */
#define NDT7_CB_HTTP_REQUEST(s) (void)fprintf(stderr, "%s", s)

/* This is the callback called when we receive an HTTP header from the
 * server when we're upgrading to WebSocket. */
#define NDT7_CB_HTTP_RESPONSE_HEADER(s) (void)fprintf(stderr, "%s\n", s)
#endif
/* This is the callback called when we receive a measurement from the
 * server. We currently only receive download measurements. Because the
 * m-lab/ndt-server server adds a newline after each serialized JSON
 * message sent over the WebSocket, we don't need to add one. */
#define NDT7_CB_NDT7_ON_MEASUREMENT_PART(p, n)                                 \
  do {                                                                         \
    (void)fwrite(p, 1, n, stdout);                                             \
    fflush(stdout);                                                            \
  } while (0)

/* This is the callback called when we have an application level measurement
 * during the upload. We emit a JSON on the standard output. */
#define NDT7_CB_NDT7_ON_APP_INFO_UPLOAD(elapsed, total)                                                                                         \
  do {                                                                                                                                          \
    double elapsed_sec = (double)elapsed / 1000.0;                                                                                              \
    fprintf(stdout, "{\"Upload speed:\": %f, \"elapsed\": %f, \"app_info\": {\"num_bytes\": %zu}}\n", total / elapsed_sec, elapsed_sec, total); \
    fflush(stdout);                                                                                                                             \
  } while (0)

/* This is the callback called when an OpenSSL function fails. */
#define NDT7_CB_TLS_ERROR(what)                                                \
  do {                                                                         \
    fprintf(stderr, "=== BEGIN %s FAILURE LOG ===\n", what);                   \
    if (errno != 0) {                                                          \
      fprintf(stderr, "system error: %s\n", strerror(errno));                  \
    }                                                                          \
    ERR_print_errors_fp(stderr);                                               \
    fprintf(stderr, "=== END %s FAILURE LOG ===\n", what);                     \
  } while (0)

#include "libndt7-unix-openssl.h"

/* If you provide this macro at compile time, you can override the default
 * location that is used for the CA bundle path. */
#ifndef CA_BUNDLE_PATH
#define CA_BUNDLE_PATH "/etc/ssl/cert.pem" /* macOS default */
#endif

static void usage(FILE *fp) {
  fprintf(fp, "usage: ndt7-unix-openssl [options] -hostname <HOSTNAME>\n");
  fprintf(fp, "\n");
  fprintf(fp, "options:\n");
  fprintf(fp, "  -ca-bundle-path <PATH>: sets CA bundle path\n");
  fprintf(fp, "  -port <PORT>: sets port to use\n");
  fprintf(fp, "  -timeout <SECONDS>: timeout for the test\n");
  fprintf(fp, "\n");
  fprintf(fp, "This program prints JSON messages containing the\n");
  fprintf(fp, "performance measurements on the stdout.\n");
  fprintf(fp, "\n");
  fprintf(fp, "Log messages go on the stderr.\n");
  fprintf(fp, "\n");
  fprintf(fp, "The exitcode is zero on success, nonzero on failure.\n");
  fprintf(fp, "\n");
  fprintf(fp, "Ideally, you want to call mlab-ns and drive this\n");
  fprintf(fp, "program from an higher level software written in a\n");
  fprintf(fp, "much more user friendly language (e.g. bash).\n");
  exit(1);
}

int main(int argc, char **argv) {
  (void)argc;
  const char *hostname = NULL;
  const char *port = "443";
  const char *ca_bundle_path = CA_BUNDLE_PATH;
  unsigned int timeout = 45;
  for (++argv; *argv != NULL; ++argv) {
    if (strcmp(*argv, "-ca-bundle-path") == 0) {
      ca_bundle_path = *++argv;
    } else if (strcmp(*argv, "-hostname") == 0) {
      hostname = *++argv;
    } else if (strcmp(*argv, "-port") == 0) {
      port = *++argv;
    } else if (strcmp(*argv, "-timeout") == 0) {
      int t = atoi(*++argv);
      if (t <= 0) {
        fprintf(stderr, "FATAL: timeout must be a positive integer.\n");
        exit(1);
        /* NOTREACHED */
      }
      timeout = (unsigned int)t;
    } else {
      usage(stderr);
      /* NOTREACHED */
    }
  }
  if (hostname == NULL) {
    CURL *curl;
    CURLcode res;
    curl = curl_easy_init();
    if (curl) {
      struct string_result s;
      init_string(&s);
      curl_easy_setopt(curl, CURLOPT_URL, "https://locate-dot-mlab-staging.appspot.com/ndt_ssl?policy=geo_options");
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
      res = curl_easy_perform(curl);
      char *ret;
      ret = extractFqdn(s.ptr, "\"fqdn\":");
      ret[strlen(ret) - 2] = 0;
      memmove(ret, ret + 1, strlen(ret));
      hostname = ret;
      //free(s.ptr);

      /* always cleanup */
      curl_easy_cleanup(curl);
    }
  }
  (void)alarm(timeout);
  (void)signal(SIGPIPE, SIG_IGN);
  (void)SSL_library_init();
  (void)SSL_load_error_strings();
  struct ndt7_settings settings;
  memset(&settings, 0, sizeof(settings));
  settings.hostname = hostname;
  settings.port = port;
  settings.ca_bundle_path = ca_bundle_path;
  int exitcode = 0;
  int ret = ndt7_download(&settings);
  if (ret != 0) {
    fprintf(stderr, "WARNING: cannot start download (code: %d)\n", ret);
    ++exitcode;
  }
  ret = ndt7_upload(&settings);
  if (ret != 0) {
    fprintf(stderr, "WARNING: cannot start upload (code: %d)\n", ret);
    ++exitcode;
  }
  return exitcode;
}
