# ndt7-unix-openssl

This is a stripped down [libndt](https://github.com/measurement-kit/libndt)
that only implements ndt7 and only works on Unix systems with OpenSSL 1.0.2+.

## Design

It is less flexible than libndt, for example in the way in which
timeouts are specified, or in that this library does not implement
[mlab-ns](https://github.com/m-lab/mlab-ns). While libndt was meant
to be included into larger pieces of software (e.g.
[OONI](https://github.com/ooni)), this library is meant to be used
to implement a very limited program that can be controlled externally
by a more complex piece of software in a Unix system. This design choice
allowed to cut down lots of complexity.

## Library

The `libndt7-unix-openssl.h` header contains the library API and the inline
implementation of such API. To integrate this code into your repository,
just copy the header into it and include it. Make sure you read about the
caveats and assumptions made by the library before using it. They are
described in the toplevel comment of the header.

There are a bunch of places where the implementation could be improved to
be more compliant with WebSocket and/or more flexible. They are marked as
TODO comments inside of the `libndt7-unix-openssl.h` header.

## Executables

The `ndt7-unix-openssl.c` source file contains an example of usage of the
library, where all the caveats have been addressed in the proper way.

There is also the `ndt7-unix-openssl.bash` script that shows how to wrap
wrap `ndt7-unix-openssl` to run a test from command line without having
to know the proper M-Lab server. This script assumes that you have installed
the `curl` and `jq` packages and that `ndt7-unix-openssl` is in the same
directory in which the script is.

## Build instructions

This is a CMake based repository. Just run `cmake .` to configure the
build and `make` to build. You'll need to have installed `make`, a
recent version of `gcc`, and the OpenSSL development package. The code
should work with OpenSSL 1.0.2+ and LibreSSL.

Note that, by default, this code assumes that the CA bundle path is
at `/etc/ssl/cert.pem`. Change this by setting

```
export CFLAGS="-DCA_BUNDLE_PATH=/path/to/CA/bundle
```

_before_ running CMake.

Note that, by default, the library performs TLS certificate verification
and you need to `export CFLAGS="-DNDT7_INSECURE"` to disable that. Make
sure you export that variable _before_ running CMake.

As an implementation detail, we currently use [MKBuild](
https://github.com/measurement-kit/mkbuild) to keep
the [CMakeLists.txt](CMakeLists.txt) file up to date. Refer to the
documentation of MKBuild for how to do that.
