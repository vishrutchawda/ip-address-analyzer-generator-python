# IP Address Analyzer 🌐

A comprehensive desktop application built with Python and Tkinter for analyzing and generating IPv4 addresses. This tool supports both classful and classless IP addressing schemes, making it ideal for networking students, professionals, and anyone working with IP address management.

![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

## 📋 Table of Contents
- [Features](#features)
- [Screenshots](#screenshots)
- [Installation](#installation)
- [Usage](#usage)
  - [Analyze IP Addresses](#analyze-ip-addresses)
  - [Generate IP Networks](#generate-ip-networks)
- [Technical Details](#technical-details)
- [Requirements](#requirements)
- [How It Works](#how-it-works)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)

## ✨ Features

### IP Address Analysis
- **Dual Format Support**: Accepts IP addresses in both decimal (e.g., 192.168.1.1) and binary (e.g., 11000000.10101000.00000001.00000001) formats [web:7]
- **Classful Analysis**: Automatically identifies IP class (A, B, C, D, or E) with detailed network information
- **Classless Analysis**: Supports CIDR notation for subnet calculations
- **Comprehensive Output**: Provides network ID, broadcast IP, subnet mask, usable IP range, and host capacity
- **IP Type Detection**: Distinguishes between private and public IP addresses
- **Format Conversion**: Converts between binary and decimal representations

### IP Network Generation
- **Automated Network Creation**: Generates multiple network configurations based on host requirements
- **Classful Generation**: Creates networks following traditional class-based addressing
- **Classless Generation**: Uses VLSM (Variable Length Subnet Masking) for efficient address allocation
- **Private/Public Options**: Supports both private and public IP address ranges
- **Scalable Output**: Generates up to thousands of networks with detailed subnet information

### User Interface
- **Modern GUI**: Clean, intuitive interface built with Tkinter and ttk widgets
- **Real-time Validation**: Instant feedback on IP address format and validity
- **Animated Results**: Smooth text rendering with visual feedback
- **Responsive Design**: Organized layout with scrollable results area
- **Interactive Controls**: Radio buttons, dropdown menus, and hover effects

## 🚀 Installation

### Prerequisites
- Python 3.7 or higher
- tkinter (usually comes pre-installed with Python)

### Steps

1. **Clone the repository**
git clone https://github.com/vishrutchawda/ip-address-analyzer-generator-python.git
cd ip-address-analyzer-generator-python

2. **Verify Python installation**
python --version

3. **Run the application**
python ip_solver.py

> **Note**: On some systems, you may need to use `python3` instead of `python`

## 💻 Usage

### Analyze IP Addresses

1. **Select Functionality**: Choose "Analyze IP" from the dropdown menu
2. **Enter IP Address**: Input an IP in decimal (192.168.1.1) or binary (11000000.10101000.00000001.00000001) format
3. **Choose Analysis Type**:
   - **Classful**: Automatically determines class and network parameters
   - **Classless**: Requires CIDR prefix (e.g., /24) for custom subnetting
4. **Click Analyze**: View comprehensive network information

#### Example Output (Classful)
Class :- c

Description :- Class C :- Used for small networks.

IP Type :- Private

IP in Binary :- 11000000.10101000.00000001.00000001

Network id bit :- 24

Host id bit :- 8

Subnet mask :- 255.255.255.0

Network IP :- 192.168.1.0

Broadcast IP :- 192.168.1.255

No. of networks :- 2 ^ 21

No. of host per network :- 2 ^ 8 approx , actual: 254

### Generate IP Networks

1. **Select Functionality**: Choose "Generate IP" from the dropdown menu
2. **Enter Device Count**: Specify the number of hosts needed per network
3. **Select IP Category**: Choose between Private or Public IP ranges
4. **Choose Generation Type**:
   - **Classful**: Uses traditional Class A, B, or C networks
   - **Classless**: Calculates optimal CIDR prefix for efficiency
5. **Click Generate**: View multiple network configurations

#### Example Output
Network 192.168.0.0:
Network ID bit :- 24
Host ID bit :- 8
Subnet Mask in binary :- 11111111.11111111.11111111.00000000
Subnet Mask in decimal :- 255.255.255.0
Network IP :- 192.168.0.0
Broadcast IP :- 192.168.0.255
Usable IP Range :- 192.168.0.1 - 192.168.0.254
No. of host per network :- 2 ^ 8 approx , actual: 254

... and 250 more networks can be created.

## 🔧 Technical Details

### IP Validation
The application performs rigorous validation to ensure IP address integrity [web:6]:
- Verifies exactly 4 octets separated by periods
- Checks for proper decimal range (0-255) or binary format (8 bits)
- Prevents mixing of binary and decimal formats
- Rejects leading zeros in decimal notation
- Validates CIDR prefix range (1-31)

### Private IP Address Ranges
Automatically detects private IP addresses based on RFC 1918:
- **Class A**: 10.0.0.0/8
- **Class B**: 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
- **Class C**: 192.168.0.0/16

### IP Class Detection
**Binary-based Detection**:
- Class A: First bit is 0 (0xxxxxxx)
- Class B: First two bits are 10 (10xxxxxx)
- Class C: First three bits are 110 (110xxxxx)
- Class D: First four bits are 1110 (1110xxxx)
- Class E: First four bits are 1111 (1111xxxx)

**Decimal-based Detection**:
- Class A: 0-127
- Class B: 128-191
- Class C: 192-223
- Class D: 224-239 (Multicast)
- Class E: 240-255 (Reserved)

### Network Calculations
**Classful**:
- Uses default subnet masks (255.0.0.0, 255.255.0.0, 255.255.255.0)
- Calculates networks based on class boundaries
- Provides network and broadcast addresses

**Classless (CIDR)**:
- Dynamically calculates subnet mask from prefix length
- Uses bitwise operations for network/broadcast calculation
- Determines optimal prefix based on host requirements
- Calculates usable IP range (excludes network and broadcast)

## 📦 Requirements
Python 3.7+
tkinter (built-in)

No external dependencies required! The application uses only Python standard library modules.

## 🔍 How It Works

### Architecture
The application follows a modular design pattern with clear separation of concerns [web:7]:

1. **Validation Layer**: `validate_ip()` ensures data integrity
2. **Analysis Engine**: 
   - `analyze_classfull()`: Processes class-based addressing
   - `analyze_classless()`: Handles CIDR calculations
3. **Generation Engine**:
   - `generate_classful()`: Creates traditional networks
   - `generate_classless()`: Implements VLSM
4. **Conversion Utilities**: `ip_to_binary()`, `ip_to_int()`, `int_to_ip()`
5. **GUI Layer**: Tkinter-based interface with event handling

### Key Algorithms

**Subnet Mask Generation (CIDR)**:
subnet = ['1'] * netbit + ['0'] * (32 - netbit)
subnetmask_bin = '.'.join([''.join(subnet[i:i+8]) for i in range(0, 32, 8)])

**Network IP Calculation**:
networkip = [ip & mask for ip, mask in zip(ip_parts, subnet_parts)]

**Broadcast IP Calculation**:
broadcastip = [ip | (255 - mask) for ip, mask in zip(ip_parts, subnet_parts)]

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork the repository**
2. **Create a feature branch**
git checkout -b feature/AmazingFeature
3. **Commit your changes**
git commit -m 'Add some AmazingFeature'
4. **Push to the branch**
git push origin feature/AmazingFeature
5. **Open a Pull Request**

### Ideas for Contribution
- Add IPv6 support
- Implement subnet calculator for complex scenarios
- Create a command-line interface (CLI) version
- Add export functionality (CSV, JSON, PDF)
- Implement dark mode theme
- Add internationalization (i18n) support
- Create unit tests for validation functions
- Add network topology visualization

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Vishrut Chawda**

- GitHub: [@vishrutchawda](https://github.com/vishrutchawda)
- LinkedIn: [Vishrut Chawda](https://www.linkedin.com/in/gp-avpti-comp-vishrut-chawda-s236020307230/) [web:1]

## 🙏 Acknowledgments

- Built with Python and Tkinter
- Inspired by networking concepts from computer networks curriculum
- Thanks to the open-source community for continuous inspiration

## 📚 Resources

For learning more about IP addressing and subnetting:
- [RFC 791 - Internet Protocol](https://tools.ietf.org/html/rfc791)
- [RFC 1918 - Address Allocation for Private Internets](https://tools.ietf.org/html/rfc1918)
- [RFC 4632 - Classless Inter-domain Routing (CIDR)](https://tools.ietf.org/html/rfc4632)

---

**⭐ If you find this project useful, please consider giving it a star!**

