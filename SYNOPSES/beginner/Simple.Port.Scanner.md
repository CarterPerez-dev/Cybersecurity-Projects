# Simple Port Scanner

## Overview
Build a Python script that efficiently scans common ports on a target IP address to identify which services are running and responding. This project teaches socket programming, concurrent execution, and basic network reconnaissance techniques that are fundamental to cybersecurity work.

## Step-by-Step Instructions

1. **Set up your Python environment** by installing any required libraries (primarily `socket`, which comes built-in, but you may want `asyncio` for concurrent operations). Create a new project directory and start with a basic script that imports these modules and validates command-line arguments for target IP and port range.

2. **Implement sequential socket connections** to individual ports by creating a function that attempts to connect to a specific IP and port combination using the `socket` library. Set a timeout value (2-3 seconds) so the script doesn't hang on unresponsive ports, and catch connection exceptions to gracefully handle failures.

3. **Add threading or asyncio for concurrent scanning** to dramatically speed up the process, since scanning 65,535 ports sequentially could take hours. Create a thread pool or async task group that manages multiple concurrent connections, ensuring you don't overwhelm the target system by limiting concurrent connections to a reasonable number (e.g., 50-100 threads).

4. **Implement banner grabbing** to identify services by attempting to read response data from open ports—many services send identifying information when you connect (like "SSH-2.0-OpenSSH_7.4"). Store this banner data along with port information for better service identification.

5. **Add service detection logic** by cross-referencing known port numbers with a common services database (you can hardcode a dictionary of standard port-to-service mappings like 22→SSH, 80→HTTP, 443→HTTPS, 3306→MySQL, etc.).

6. **Create a clean output format** that displays results in an organized table or list showing port number, status (open/closed), protocol, and detected service. Use color coding (green for open, red for closed) to make results easier to scan quickly.

7. **Implement command-line argument parsing** to make your tool flexible, accepting parameters like target IP, port range (e.g., 1-1024 for common ports or 1-65535 for full scan), and timeout values. Add a help menu that explains how to use the tool properly.

8. **Test your scanner thoroughly** on localhost first (your own machine) using test servers or services you know are running. Document the limitations and best practices, including warnings that port scanning may violate acceptable use policies on networks you don't own—stress that this tool should only be used on systems and networks you have explicit permission to scan.

## Key Concepts to Learn
- Socket programming and TCP/IP connections
- Threading and concurrency for performance optimization
- Error handling and timeouts
- Banner grabbing for service detection
- Command-line interfaces and argument parsing

## Deliverables
- Functional Python script with concurrent scanning capability
- Output showing open ports with detected services
- Documentation with usage examples and ethical guidelines
