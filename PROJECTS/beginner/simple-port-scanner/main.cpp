#include "src/PortScanner.hpp"
#include <boost/program_options.hpp>
namespace po = boost::program_options;

int main(int argc, char* argv[]) {

	po::options_description desc("Allowed options");
	desc.add_options()
		("help,h", "produce help message")
		("dname,i", po::value<std::string>()->default_value("127.0.0.1"), "set domain name or IP address")
		("ports,p", po::value<std::string>()->default_value("1-1024"), "set a port range from 1 to n")
		("threads,t", po::value<int>()->default_value(100), "max concurrent threads")
		("expiry_time,e", po::value<uint8_t>()->default_value(2)->value_name("sec"), "timeout in seconds")
		("verbose,v", "verbose output");

	po::variables_map vm;
	po::store(po::parse_command_line(argc, argv, desc), vm);
	po::notify(vm);

	if (vm.count("help")) {
		std::cout << desc << "\n";
		std::cout << "Examples:\n"
			  << "  Scan common ports on localhost:\n"
			  << "    ./port_scanner -i 127.0.0.1 -p 1-1024\n\n"
			  << "  Full TCP port scan:\n"
			  << "    ./port_scanner -i 192.168.1.1 -p 65535 -t 200\n\n"
			  << "  Scan with custom timeout:\n"
			  << "    ./port_scanner -i example.com -p 80-443 -e 5\n\n"
			  << "  Postscriptum:\n"
			  << "  Scan only systems you own or have explicit permission to test.\n";
		return 0;
	}
	std::string ip = vm["dname"].as<std::string>();
	std::string port = vm["ports"].as<std::string>();
	int threads = vm["threads"].as<int>();
	uint8_t expiry_time = vm["expiry_time"].as<uint8_t>();

	PortScanner scanner;
	scanner.set_options(ip, port, threads, expiry_time);
	scanner.start();
	scanner.run();

	return 0;
}
