#include <cstdio>
#include <thread>
#include "mdns.hpp"

int
main() {
	mdns::Logger::setLoggerSink(
	    [](const std::string& message) { printf("[Verbose MDNS] %s\n", message.c_str()); });

	std::string host_name = mdns::get_host_name();

	std::map<const char*, const char*> txtRecords;
	txtRecords["version"] = "1.0.0";
	// txtRecords["key2"] = "value2";

	mdns::MDNSService darknet_service(host_name, "_darknet._tcp.local.", 4242, txtRecords);
	mdns::MDNSService my_weberver_service(host_name, "_http._tcp.local.", 8080, {});

	auto res_darknet = darknet_service.start();
	auto res_webserver = my_weberver_service.start();

	// serve for 3 seconds and send "Goodbye" packet
	// std::this_thread::sleep_for(std::chrono::seconds(10));

	// or serve forever
	res_darknet.wait();
	res_webserver.wait();

	darknet_service.stop();
	my_weberver_service.stop();

	printf("Service stopped\n");
	return 0;
}