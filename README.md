# TrafficBRO
A super simple packet analyzer 


## Table of contents
* [Intro](#intro)
* [Features](#features)
* [Setup](#setup)
* [HowTo](#howto)

## Intro
As a detection engineer analyzing PCAP files, you should focus on extracting the following key fields:

1. IP Addresses
- Source IP: Identify where the traffic is coming from.
- Destination IP: Identify where the traffic is going.

2. Ports
- Source Port: The port number on the sending side.
- Destination Port: The port number on the receiving side.

3. Protocols
- Protocol Type: Common types include TCP, UDP, ICMP, and others. Identifying the protocol helps categorize the traffic.

4. Packet Length
- Size: The length of each packet can indicate anomalies (e.g., unusually large or small packets).

5. Flags (for TCP)
- TCP Flags: SYN, ACK, FIN, RST, PSH, URG. These indicate the state of a TCP connection.

6. Payload Information
- Payload Size: Analyze the content size of the packets, especially for suspicious patterns.
- Application Layer Protocol: If applicable, identify protocols like HTTP, DNS, etc.

7. Timestamps
- Capture Time: The time when each packet was captured helps in analyzing traffic patterns over time.

8. Sequence and Acknowledgment Numbers (for TCP)
- Sequence Number: Used to identify the order of packets.
- Acknowledgment Number: Indicates receipt of packets.

9. Session Information
- Connection Duration: Calculate the duration of established connections.

10. DNS Queries and Responses
- Query Type: Identify DNS request types (A, AAAA, MX, etc.).
- Query Name: The domain names being queried.

11. ICMP Types and Codes
- Type: Identifies the nature of the ICMP message (e.g., echo request, destination unreachable).
- Code: Provides further detail about the ICMP message type.

12. TLS/SSL Information
- Certificate Details: If applicable, extract certificate information for HTTPS traffic.

13. Anomalous Behavior Indicators
- Repeated Connections: Frequent connections to unusual or unexpected ports.
- Uncommon Protocols: Usage of non-standard or rarely seen protocols.

14. Geolocation Information
- Geolocation Mapping: Map IP addresses to geographical locations for threat analysis.


Source IP: Originating IP address

Destination IP:	Target IP address

Source Port: Port number on the sending side

Destination Port: Port number on the receiving side

Protocol Type: TCP, UDP, ICMP, etc.

Packet Length: Size of the packet

TCP Flags: SYN, ACK, FIN, RST, etc.

Payload Size: Size of the payload

Capture Time: Timestamp of packet capture

Sequence Number: TCP sequence number

Acknowledgment Number:	TCP acknowledgment number

DNS Query Type:	Type of DNS request

DNS Query Name:	Name queried in DNS

ICMP Type: Type of ICMP message

ICMP Code: Code of ICMP message

TLS/SSL Certificate: Certificate details for HTTPS traffic

Connection Duration: Duration of established connections

Anomalous Behavior Indicators: Repeated connections, uncommon protocols

By focusing on these fields, you can effectively analyze traffic, identify potential threats, and develop detection rules to enhance your security posture.

## Features
- Extracts IP's, Ports, Protocol Types, Packet Length, Payload size, Capture Time, Sequence number, DNS info, ICMP info, TLS/SSL info, Behavior from a pcap file
- Output unique results from the pcap file
- Give you the ability to quickly search through multiple pcap files

## Setup

### Prerequisites

#### Enviroment
```
1.) ensure you have python 3.x installed 
$ python3 -m venv /path/you/want/the/env/in
$ source /path/you/want/the/env/in/bin/activate 
```
#### Clone repository 

        $ git clone https://github.com/ChalkingCode/TrafficBRO.git
        $ cd TrafficBRO


#### Install Packages on env
```       
Scappy

# This only needs to be ran once per env 
$ pip install -r requirements.txt
```

## HowTo
