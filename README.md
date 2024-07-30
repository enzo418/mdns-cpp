# Simple C++ Wrapper for the Public domain mDNS/DNS-SD library in C
Check the original [README.md](README_original.md) for the original documentation.

## Features
- **Service Announcing** [`example_serve.cpp`](example_serve.cpp)
- **Querying for a service and listening for "Goodbye"** [`example_client.cpp`](example_client.cpp)

## Logging
To disable logging, set the cmake option `MDNS_CPP_DISABLE_LOGGING` to `ON` and recompile the project.