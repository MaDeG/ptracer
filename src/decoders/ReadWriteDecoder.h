#ifndef PTRACER_READWRITEDECODER_H
#define PTRACER_READWRITEDECODER_H

#include <fstream>
#include <set>
#include "SyscallDecoder.h"

struct OutFile {
	std::filesystem::path path;
	std::ofstream outStream;
};

class ReadWriteDecoder : public SyscallDecoder {
public:
	static void registerAt(ProcessSyscallDecoderMapper& mapper);
	bool decode(const ProcessSyscallEntry& syscall) override;
	bool decode(const ProcessSyscallExit& syscall) override;
	void printReport() const override;
private:
	static const std::set<int> WRITE_SYSCALLS;
	static const std::set<int> READ_SYSCALLS;
	static const std::filesystem::path root;
	std::map<int, OutFile> readOutputs;
	std::map<int, OutFile> writeOutputs;
	static inline bool isWrite(int syscall);
	static std::ofstream* getOfstream(const ProcessSyscallEntry& syscall, std::map<int, OutFile>& map, std::string append);
};

#endif //PTRACER_READWRITEDECODER_H
