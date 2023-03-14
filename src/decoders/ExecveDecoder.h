#ifndef PTRACER_EXECVEDECODER_H
#define PTRACER_EXECVEDECODER_H

#include "SyscallDecoder.h"

struct ExecCall {
	std::string path;
	std::vector<std::string> argv;
};

class ExecveDecoder : public SyscallDecoder {
public:
	static void registerAt(ProcessSyscallDecoderMapper& mapper);
	bool decode(const ProcessSyscallEntry& syscall) override;
	bool decode(const ProcessSyscallExit& syscall) override;
	void printReport() const override;
private:
	std::vector<ExecCall> executables;
};

#endif //PTRACER_EXECVEDECODER_H
