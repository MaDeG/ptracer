#include <arpa/inet.h>
#include <boost/format.hpp>
#include <iostream>
#include <sys/syscall.h>
#include "ConnectDecoder.h"

using namespace std;

unordered_map<unsigned short, std::string> ConnectDecoder::socketFamilies;

bool ConnectDecoder::decode(const ProcessSyscallEntry& syscall) {
	// TODO: Malicious tracees could set very big length to try to make the tracer crash
	char* extractedBytes = syscall.getTracer()->extractBytes(syscall.argument(1), syscall.argument(2));
	struct sockaddr* addr = reinterpret_cast<sockaddr*>(extractedBytes);
	this->connectCalls.push_back(ConnectDecoder::makeCall(syscall, addr));
	delete[] extractedBytes;
	return true;
}

/**
 * This decoder does not handle exit syscall notifications.
 *
 * @param syscall The exit syscall notification
 * @return Always true.
 */
bool ConnectDecoder::decode(const ProcessSyscallExit& syscall) {
	return true;
}

void ConnectDecoder::registerAt(ProcessSyscallDecoderMapper& mapper) {
	if (ConnectDecoder::socketFamilies.empty()) {
		ConnectDecoder::initFamilies();
	}
	shared_ptr<SyscallDecoder> thisDecoder(new ConnectDecoder());
	mapper.registerEntrySyscallDecoder(SYS_connect, thisDecoder);
}

/**
 * Prints a report of all the opened paths observed.
 */
void ConnectDecoder::printReport() const {
	cout << "------------------ CONNECT DECODER START ------------------" << endl;
	for (const ConnectCall& call : this->connectCalls) {
		cout << "Family: " << call.family << ", to address: " << call.address;
		if (call.port > 0) {
			cout << " : " << call.port;
		}
		cout << endl;
	}
	cout << "------------------ CONNECT DECODER STOP ------------------" << endl;
}

void ConnectDecoder::initFamilies() {
	ConnectDecoder::socketFamilies[AF_UNSPEC] = "Unspecified";;
	ConnectDecoder::socketFamilies[AF_UNIX] = "UNIX socket";
	ConnectDecoder::socketFamilies[AF_LOCAL] = "Local socket";
	ConnectDecoder::socketFamilies[AF_INET] = "IPv4 Internet protocol";
	ConnectDecoder::socketFamilies[AF_BRIDGE] = "Bridge links";
	ConnectDecoder::socketFamilies[AF_INET6] = "IPv6 Internet protocol";
	ConnectDecoder::socketFamilies[AF_NETLINK] = "Kernel-Userspace communication";
	ConnectDecoder::socketFamilies[AF_ROUTE] = "Kernel-Userspace communication";
	ConnectDecoder::socketFamilies[AF_BLUETOOTH] = "Bluetooth";
	ConnectDecoder::socketFamilies[AF_PACKET] = "Low-level packet interface";
	ConnectDecoder::socketFamilies[AF_PPPOX] = "PPP transport layer";
	ConnectDecoder::socketFamilies[AF_IEEE802154] = "IEEE 802.15.4 WPAN";
}

std::string ConnectDecoder::inetToString(const unsigned short family, const in_addr& addr) {
	if(family != AF_INET && family != AF_INET6) {
		return (boost::format("%#016x") % addr.s_addr).str();
	}
	char address[16];
	inet_ntop(family, &addr, address, 16);
	return string(address);
}

ConnectCall ConnectDecoder::makeCall(const ProcessSyscallEntry& entry, sockaddr* addr) {
	string family = ConnectDecoder::socketFamilies[addr->sa_family];
	if (addr->sa_family == AF_INET || addr->sa_family == AF_INET6) {
		struct sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(addr);
		return {family,
            ntohs(sin->sin_port),
            ConnectDecoder::inetToString(sin->sin_family, sin->sin_addr)};
	} else if (addr->sa_family == AF_LOCAL) {
		return {family,
						0,
						string(addr->sa_data)};
	} else {
		return {family, 0, "Unhandled address"};
	}
}