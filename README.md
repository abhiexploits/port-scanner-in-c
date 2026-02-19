
# 🔍 Advanced Port Scanner - Professional Edition

## 📌 Project Overview
Yeh ek high-performance multi-threaded port scanner hai jo C programming language mein develop kiya gaya hai. Professional penetration testing aur network security analysis ke liye design kiya gaya hai.

---

## ✨ Key Features

### 🚀 Core Functionality
- **Multi-threaded Architecture** - 250 threads tak simultaneous scanning ki capacity
- **Intelligent Service Detection** - 50+ common ports ke service names automatically detect karta hai
- **Smart Hostname Resolution** - Domain names ko automatically IP addresses mein convert karta hai
- **Flexible Port Selection** - Specific ports ya custom ranges scan karne ki suvidha
- **Adjustable Timeout Control** - Slow ya unresponsive ports ko skip karne ki facility

### 🎨 User Interface
- **Color-coded Output** - Different colors for different types of information
- **Real-time Progress Tracking** - Live scanning progress display
- **Formatted Results** - Clean tables aur organized data presentation
- **Professional Banner** - Attractive command-line interface design

### 📊 Advanced Capabilities
- **Verbose Mode** - Detailed output with closed ports information
- **File Export** - Scan results ko text file mein save karne ki facility
- **Performance Metrics** - Scan speed aur time taken ka accurate calculation
- **Comprehensive Statistics** - Detailed analysis of scanning results
- **Robust Error Handling** - Proper validation aur error messages

---

## 🔧 Installation Guide

### System Requirements

#### For Linux Users:
```bash
sudo apt-get update
sudo apt-get install gcc make build-essential
```
#### For MacOS Users:

```bash
xcode-select --install
brew install gcc
```
#### For Windows Users (with WSL):

```bash
wsl --install
```
# Then follow Linux instructions

### Compilation Process

#### Basic compilation (recommended for beginners):

```bash
gcc -o port-scanner port-scanner.c -lpthread
```
#### Optimized compilation (for better performance):

```bash
gcc -o port-scanner port-scanner.c -lpthread -O3 -Wall -march=native
```
#### Debug compilation (for development):

```bash
gcc -o port-scanner port-scanner.c -lpthread -O0 -Wall -g -DDEBUG
```
#### Maximum optimization (for production use):

```bash
gcc -o port-scanner port-scanner.c -lpthread -O3 -Wall -flto -march=native
```
# Permission Setup

```bash
## Execute permission dena
chmod +x port-scanner
```
## Full permissions (if needed)
```bash
chmod 755 port-scanner
```
## Verify permissions
```bash
ls -la port-scanner
```
---

# 📖 Detailed Usage Manual

#### Basic Operations

#### Interactive Mode - Manual input ke liye:

```bash
./port-scanner
```
## Enter the target manually:

#### Quick Scan - Default ports (1-1024) ke saath:

```bash
./port-scanner google.com
```
#### Local Network Scan:

```bash
./port-scanner 192.168.1.1
```
#### Custom Range Scan:

```bash
./port-scanner 10.0.0.1 1 5000
```
#### Single Port Scan:

```bash
./port-scanner example.com 80 80
```
#### Advanced Operations

Complete Port Scan (1-65535):

```bash
./port-scanner target.com -p-
```
#### Multiple Specific Ports:

```bash
./port-scanner 192.168.1.100 -p 22,80,443,3306,8080
```
High-speed Scan with 200 threads:

```bash
./port-scanner example.com -p 1-5000 -t 200
```
#### Extended Timeout for Slow Connections:

```bash
./port-scanner remote-server.com -p 1-1000 -T 5
```
#### Service Detection Enabled:

```bash
./port-scanner localhost -p 1-500 -s
```
#### Verbose Output with All Details:

```bash
./port-scanner 10.0.0.5 -p 1-2000 -v
```
### Complete Professional Scan:

```bash
./port-scanner enterprise.com -p 1-10000 -t 150 -T 3 -s -v -o full_scan.txt
```
# Command Referene Table

### Option Full Form Description Example Usage
##### -p Ports Port range specification -p 1-1000
##### -t Threads Number of threads -t 150
##### -T Timeout Timeout in seconds -T 3
##### -o Output Output file name -o results.txt
##### -s Services Resolve service names -s
##### -v Verbose Verbose output -v
##### -h Help Display help menu -h

### MADE WITH LOVE❤️❤️
#### HAPPY HACKING
