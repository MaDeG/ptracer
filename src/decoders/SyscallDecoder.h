#ifndef PTRACER_SYSCALLDECODER_H
#define PTRACER_SYSCALLDECODER_H

#include "../ProcessSyscallEntry.h"
#include "ProcessSyscallDecoderMapper.h"

class SyscallDecoder {
public:
	virtual bool decode(const ProcessSyscallEntry& syscall) = 0;
	virtual bool decode(const ProcessSyscallExit& syscall) = 0;
	virtual void printReport() const = 0;
};

#endif //PTRACER_SYSCALLDECODER_H
