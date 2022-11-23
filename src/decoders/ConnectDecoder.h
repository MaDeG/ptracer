#ifndef PTRACER_CONNECTDECODER_H
#define PTRACER_CONNECTDECODER_H

#include <sys/socket.h>
#include <netinet/in.h>
#include "SyscallDecoder.h"

struct ConnectCall {
	std::string family;
	unsigned short port;
	std::string address;
};

class ConnectDecoder : public SyscallDecoder {
public:
	static void registerAt(ProcessSyscallDecoderMapper& mapper);
	bool decode(const ProcessSyscallEntry& syscall) override;
	bool decode(const ProcessSyscallExit& syscall) override;
	void printReport() const override;
private:
	static std::unordered_map<unsigned short, std::string> socketFamilies;
	static void initFamilies();
	static std::string inetToString(const unsigned short family, const in_addr& addr);
	static ConnectCall makeCall(const ProcessSyscallEntry& entry, sockaddr* addr);
	std::vector<ConnectCall> connectCalls;
};

#endif //PTRACER_CONNECTDECODER_H
