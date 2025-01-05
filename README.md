# Covert TCP Communication Tool

This repository contains the source code for a covert TCP communication channel implemented in C. The tool is designed for secure and undetectable data transmission, showcasing advanced low-level programming and networking expertise.

## Features
- Implements covert communication over TCP.
- Secure data transmission through stealth techniques.
- Modular design for easy future enhancements (e.g., encryption).

## Requirements
- GCC or any C compiler.
- A Linux-based system (tested on Ubuntu 22.04).
- Basic understanding of networking protocols (TCP/IP).

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/N111X/covertTCP.git
   cd covert-tcp
   ```
2. Compile the source code:
   ```bash
   gcc covert_tcp.c -o covert_tcp
   ```

## Usage
1. Start the server on the target machine:
   ```bash
   ./covert_tcp -s <port>
   ```
2. Start the client on the attacker's machine:
   ```bash
   ./covert_tcp -c <target_ip> <port>
   ```
3. Follow prompts to send and receive data covertly.

## Technical Details
- **Covert Transmission:** Utilizes raw sockets and custom packet crafting to blend in with legitimate network traffic.
- **Modularity:** The design allows for future extensions such as integrating encryption algorithms or modifying protocols.

## Limitations
- The current version does not include encryption, leaving transmitted data in plaintext.
- Performance may vary depending on network conditions and system configurations.

## Future Work
- Integrating encryption (e.g., AES or Vigenère cipher) for data protection.
- Implementing evasion techniques to bypass network detection systems.
- Expanding support for additional protocols (e.g., UDP).

## Disclaimer
This tool is intended for educational and research purposes only. The author is not responsible for any misuse or damage caused by the use of this tool.
