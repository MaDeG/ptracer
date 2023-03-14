#ifndef PTRACER_SOCKETDECODER_H
#define PTRACER_SOCKETDECODER_H

#include <sys/socket.h>
#include <netinet/in.h>
#include "SyscallDecoder.h"

struct AddressParameters {
	int sfd;
	std::string family;
	unsigned short port;
	std::string address;
	int errorCode = 0;
};

class SocketDecoder : public SyscallDecoder {
public:
	static void registerAt(ProcessSyscallDecoderMapper& mapper);
	bool decode(const ProcessSyscallEntry& syscall) override;
	bool decode(const ProcessSyscallExit& syscall) override;
	void printReport() const override;
private:
	static std::unordered_map<unsigned short, std::string> socketFamilies;
	static void initFamilies();
	static AddressParameters makeCall(const ProcessSyscallEntry& entry, sockaddr* addr);
	std::vector<std::unique_ptr<AddressParameters>> calls;
	std::unordered_map<pid_t, int*> active;
};

#endif //PTRACER_SOCKETDECODER_H
