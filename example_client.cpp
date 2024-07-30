#include <atomic>
#include <chrono>
#include <cstdio>
#include <thread>
#include "mdns.hpp"

int
main() {
	mdns::Logger::setLoggerSink([](const std::string& message) {
		//  printf("[Verbose MDNS] %s\n", message.c_str());
	});

	mdns::MDNSClient mdnsClient("_darknet._tcp.local.");

	std::string found_service = "";

	std::atomic_bool stop(false);
	mdnsClient.sendQuery(
	    1, stop,
	    [&found_service](std::string_view from_addr, std::string_view service_name,
	                     std::string_view instance_service_name) {
		    printf("[%s] PTR Service: %.*s Instance: %.*s\n", from_addr.data(),
		           (int)service_name.length(), service_name.data(),
		           (int)instance_service_name.length(), instance_service_name.data());

		    found_service = std::string(instance_service_name);
	    },
	    [](std::string_view from_addr, uint16_t priority, uint16_t weight, uint16_t port,
	       std::string_view host_name, std::string_view service_name) {
		    printf("[%s] SRV Service: %.*s, Host: %.*s:%d, \n", from_addr.data(),
		           (int)service_name.length(), service_name.data(), (int)host_name.length(),
		           host_name.data(), port);
	    },
	    [](std::string_view from_addr, std::string_view host_name, struct sockaddr_in addr,
	       std::string_view addr_str) {
		    printf("[%s] A Host: %s IPV4: %s\n", from_addr.data(), host_name.data(),
		           addr_str.data());
	    },
	    [](std::string_view from_addr, std::string_view host_name, struct sockaddr_in6 addr,
	       std::string_view addr_str) {
		    printf("[%s] AAAA: Host: %s IPV6: %s\n", from_addr.data(), host_name.data(),
		           addr_str.data());
	    },
	    [](std::string_view from_addr, std::string_view instance_service_name,
	       const std::unordered_map<std::string, std::string>& txtRecords) {
		    printf("[%s] TXT Instance:%s\n", from_addr.data(), instance_service_name.data());
		    for (auto& [key, value] : txtRecords) {
			    printf("  %s: %s\n", key.data(), value.data());
		    }
	    },
	    [](std::string_view from_addr, const char* entry_type, std::string_view entry_str,
	       size_t record_length, uint16_t rtype, uint16_t rclass,
	       uint32_t ttl) { printf("Unknown: %.*s\n", (int)entry_str.length(), entry_str.data()); });

	// OR
	auto start = std::chrono::high_resolution_clock::now();
	std::future<std::optional<mdns::ServiceFound>> result =
	    mdnsClient.findService(/*timeout*/ 1, /*wait_for_txt*/ true, /*wait_for_bothIP46*/ false);

	// Listen for "Goodbye Packets"
	mdnsClient.listenForGoodbye(found_service, [&found_service, &mdnsClient]() {
		printf("Service %s is gone\n", found_service.data());
	});

	result.wait();
	if (result.valid()) {
		auto service = result.get();
		if (service.has_value()) {
			auto end = std::chrono::high_resolution_clock::now();
			auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

			std::string empty;
			printf(
			    "Service found via 'findService()' in %3.2ldms: Instance=%s, Host=%s, IPV4=%s, "
			    "IPV6=%s, "
			    "Port=%d, TxTRecords=%lu\n",
			    duration.count(), service->instance_service_name.data(), service->host_name.data(),
			    service->ipv4_addr.value_or(empty).data(),
			    service->ipv6_addr.value_or(empty).data(), service->port.value(),
			    service->txtRecords.has_value() ? service->txtRecords.value().size() : 0);
		} else {
			printf("Service not found\n");
		}
	}

	printf("Listening for 5 seconds more for Goodbye messages\n");
	std::this_thread::sleep_for(std::chrono::seconds(5));

	mdnsClient.stopGoodbyeListener();

	return 0;
}