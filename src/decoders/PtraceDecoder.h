#ifndef PTRACER_PTRACEDECODER_H
#define PTRACER_PTRACEDECODER_H

#include "SyscallDecoder.h"

struct PtraceCall {
	const int command;
	const pid_t targetPid;
};

class PtraceDecoder : public SyscallDecoder {
public:
	static void registerAt(ProcessSyscallDecoderMapper& mapper);
	bool decode(const ProcessSyscallEntry& syscall) override;
	bool decode(const ProcessSyscallExit& syscall) override;
	void printReport() const override;
private:
	static std::unordered_map<int, std::string> ptraceCommands;
	static void initCommands();
	std::vector<PtraceCall> ptraceCalls;
};


#endif //PTRACER_PTRACEDECODER_H
