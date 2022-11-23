#ifndef PTRACER_SYSCALLDECODERMAPPER_H
#define PTRACER_SYSCALLDECODERMAPPER_H

#include <map>
#include "ProcessSyscallEntry.h"
#include "decoders/ProcessSyscallDecoderMapper.h"
#include "decoders/SyscallDecoder.h"

class SyscallDecoderMapper {
public:
	static bool decode(const ProcessSyscallEntry& syscall);
	static bool decode(const ProcessSyscallExit& syscall);
	static void printReport();
private:
	static std::map<pid_t, ProcessSyscallDecoderMapper> decoders;
};

#endif //PTRACER_SYSCALLDECODERMAPPER_H
