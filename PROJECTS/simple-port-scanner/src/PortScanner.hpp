#ifndef PORTSCANNER_HPP
#define PORTSCANNER_HPP
#include <boost/asio.hpp>
#include <string>
#include <queue>
#include <unordered_map>
#include <iostream>
#include <array>
#include <memory>
#include <cstdint>
#include <stdio.h>

#define RED   "\033[31m"
#define GREEN "\033[32m"
#define RESET "\033[0m"
using boost::asio::ip::tcp;
class PortScanner {
private:
	static const std::unordered_map<uint16_t, std::string> basicPorts;
	static const uint16_t MAX_PORT = 65535;
	boost::asio::io_context io;
	boost::asio::ip::tcp::resolver resolver{io};
	boost::asio::ip::tcp::endpoint endpoint;
	boost::asio::strand<boost::asio::io_context::executor_type> strand{io.get_executor()};
	std::queue<std::uint16_t> q;
	int cnt = 0;
	int MAX_THREADS = 0;
	int open_ports = 0;
	int closed_ports = 0;
	int filtered_ports = 0;

	std::string domainName;
	std::uint16_t startPort = 1;
	std::uint16_t endPort = MAX_PORT;

	std::uint8_t expiry_time;

	void scan();
	void setup_queue();
	void parse_port(std::string& port);
public:
	PortScanner(std::string& ip_address, std::string& port, int max_threads, std::uint8_t expiry_time);
	PortScanner(){}
	~PortScanner() {

	}

	void set_options(std::string& domainName, std::string& port, int max_threads, std::uint8_t expiry_time);
	void set_max_port(std::uint16_t port);
	void set_max_threads(int value);
	void set_ip_address(std::string ip);
	void set_expiry_time(std::uint8_t value);

	void start();
	void run();
};

#endif //PORTSCANNER_HPP
