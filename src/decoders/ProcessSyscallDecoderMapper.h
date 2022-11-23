#ifndef PTRACER_PROCESSSYSCALLDECODERMAPPER_H
#define PTRACER_PROCESSSYSCALLDECODERMAPPER_H

#include <map>
#include <unordered_map>
#include <set>
#include "../ProcessSyscallEntry.h"
#include "../ProcessSyscallExit.h"

class SyscallDecoder;

class ProcessSyscallDecoderMapper {
public:
	ProcessSyscallDecoderMapper();
	bool registerEntrySyscallDecoder(unsigned int syscall, std::shared_ptr<SyscallDecoder> decoder);
	bool registerExitSyscallDecoder(unsigned int syscall, std::shared_ptr<SyscallDecoder> decoder);
	bool decode(const ProcessSyscallEntry& syscall);
	bool decode(const ProcessSyscallExit& syscall);
	void printReport() const;
private:
	std::unordered_map<unsigned int, std::shared_ptr<SyscallDecoder>> entrySyscallDecoders;
	std::unordered_map<unsigned int, std::shared_ptr<SyscallDecoder>> exitSyscallDecoders;
	std::set<std::shared_ptr<SyscallDecoder>> decoders;
};


#endif //PTRACER_PROCESSSYSCALLDECODERMAPPER_H
