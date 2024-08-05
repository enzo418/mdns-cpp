# Simple C++ Wrapper for the Public domain mDNS/DNS-SD library in C
Check the original [README.md](README_original.md) for the original documentation.

## Features
- **Service Announcing** [`example_serve.cpp`](example_serve.cpp)
- **Querying for a service and listening for "Goodbye"** [`example_client.cpp`](example_client.cpp)

## Logging
To disable logging, set the cmake option `MDNS_CPP_DISABLE_LOGGING` to `ON` and recompile the project.

## Server Configuration
the configuration should be done in mdns_config.cfg file in the same directory as the executable file. Or set the MDNS_CONFIG_FILE
environment variable to the path of the configuration file.

configuration values: (see mdns_configuration_t struct)
```c++
struct mdns_configuration_t {
	bool parsed = false;

	// Interface address to bind to when listening/sending for multicast packets
	// in the service mode.
	// If set to 0, INADDR_ANY (0.0.0.0) will be used.
	// NOTE: This doesn't mean the A record will have this address
	std::optional<std::string> service_multicast_ipv4_address;

	// Interfaces to ignore basde on its name or description
	// e.g. "(Hyper-V(.*))|(VirtualBox(.*))"
	std::optional<std::regex> ignore_interface_regex;
};
```
