#include <arpa/inet.h>
#include <boost/format.hpp>
#include <iostream>
#include <sys/syscall.h>
#include <sys/un.h>
#include "SocketDecoder.h"
#include "../Tracer.h"

using namespace std;

unordered_map<unsigned short, std::string> SocketDecoder::socketFamilies;

bool SocketDecoder::decode(const ProcessSyscallEntry& syscall) {
	// TODO: Malicious tracees could set very big length to try to make the tracer crash
	auto* addr = (sockaddr*) syscall.getTracer()->extractBytes(syscall.argument(1), syscall.argument(2));
	if (!addr) {
		return false;
	}
	unique_ptr<AddressParameters> parameters = make_unique<AddressParameters>(SocketDecoder::makeCall(syscall, addr));
	this->active[syscall.getSpid()] = &parameters->errorCode;
	this->calls.push_back(move(parameters));
	delete[] addr;
	return true;
}

/**
 * This decoder does not handle exit syscall notifications.
 *
 * @param syscall The exit syscall notification
 * @return Always true.
 */
bool SocketDecoder::decode(const ProcessSyscallExit& syscall) {
	assert(this->active.find(syscall.getSpid()) != this->active.end());
	*(this->active.find(syscall.getSpid())->second) = (int) syscall.getReturnValue();
	return true;
}

void SocketDecoder::registerAt(ProcessSyscallDecoderMapper& mapper) {
	if (SocketDecoder::socketFamilies.empty()) {
		SocketDecoder::initFamilies();
	}
	shared_ptr<SyscallDecoder> thisDecoder(new SocketDecoder());
	mapper.registerEntrySyscallDecoder(SYS_connect, thisDecoder);
	mapper.registerExitSyscallDecoder(SYS_connect, thisDecoder);
	//mapper.registerEntrySyscallDecoder(SYS_bind, thisDecoder);
	//mapper.registerEntrySyscallDecoder(SYS_accept, thisDecoder);
	//TODO:  Investigate socketpair
	//TODO: Finish to integrate bind and accept
}

/**
 * Prints a report of all the opened paths observed.
 */
void SocketDecoder::printReport() const {
	cout << "------------------ SOCKET DECODER START ------------------" << endl;
	for (auto& call : this->calls) {
		cout << "Socket File Descriptor: " << call->sfd << " <---> " << call->family << ", to address: [" << call->address << "]";
		if (call->family != SocketDecoder::socketFamilies[AF_UNIX]) {
			cout << ":" << call->port;
		}
		if (call->errorCode) {
			cout << ", error: " << call->errorCode << ", " << strerror(-call->errorCode);
		}
		cout << endl;
	}
	cout << "------------------ SOCKET DECODER STOP ------------------" << endl;
}

void SocketDecoder::initFamilies() {
	SocketDecoder::socketFamilies[AF_UNSPEC] = "Unspecified";;
	SocketDecoder::socketFamilies[AF_UNIX] = "UNIX socket";
	SocketDecoder::socketFamilies[AF_LOCAL] = "Local socket";
	SocketDecoder::socketFamilies[AF_INET] = "IPv4 Internet protocol";
	SocketDecoder::socketFamilies[AF_BRIDGE] = "Bridge links";
	SocketDecoder::socketFamilies[AF_INET6] = "IPv6 Internet protocol";
	SocketDecoder::socketFamilies[AF_NETLINK] = "Kernel-Userspace communication";
	SocketDecoder::socketFamilies[AF_ROUTE] = "Kernel-Userspace communication";
	SocketDecoder::socketFamilies[AF_BLUETOOTH] = "Bluetooth";
	SocketDecoder::socketFamilies[AF_PACKET] = "Low-level packet interface";
	SocketDecoder::socketFamilies[AF_PPPOX] = "PPP transport layer";
	SocketDecoder::socketFamilies[AF_IEEE802154] = "IEEE 802.15.4 WPAN";
}

AddressParameters SocketDecoder::makeCall(const ProcessSyscallEntry& entry, sockaddr* addr) {
	char address[40] = "Erroneous Address";
	int sfd = entry.argument(0);
	string family = SocketDecoder::socketFamilies[addr->sa_family];
	switch (addr->sa_family) {
		case AF_INET: {
			auto* sin = (sockaddr_in*) (addr);
			inet_ntop(addr->sa_family, &sin->sin_addr, address, sizeof(address));
			return {sfd, family, ntohs(sin->sin_port), string(address)};
		}
		case AF_INET6: {
			auto* sin6 = (sockaddr_in6*) (addr);
			inet_ntop(addr->sa_family, &sin6->sin6_addr, address, sizeof(address));
			return {sfd, family, ntohs(sin6->sin6_port), string(address)};
		}
		case AF_LOCAL: {
			auto* sun = (sockaddr_un*) (addr);
			return {sfd, family, 0, string(sun->sun_path)};
		}
		default: {
			return {sfd, family, 0, (boost::format("Unhandled address data: %#018x") % addr->sa_data).str()};
		}
	}
}