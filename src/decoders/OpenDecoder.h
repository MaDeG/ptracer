#ifndef PTRACER_OPENDECODER_H
#define PTRACER_OPENDECODER_H

#include "SyscallDecoder.h"

struct PathFD {
	std::string path;
	int fd;
};

class OpenDecoder : public SyscallDecoder {
public:
	static void registerAt(ProcessSyscallDecoderMapper& mapper);
	bool decode(const ProcessSyscallEntry& syscall) override;
	bool decode(const ProcessSyscallExit& syscall) override;
	void printReport() const override;
private:
	std::vector<PathFD> paths;
	std::unordered_map<pid_t, PathFD*>  awaitingFD;
	OpenDecoder() = default;
};

#endif //PTRACER_OPENDECODER_H
