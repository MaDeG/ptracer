#ifndef PTRACER_FILEDECODER_H
#define PTRACER_FILEDECODER_H

#include <filesystem>
#include <fstream>
#include <utility>
#include "SyscallDecoder.h"

struct PathFD {
	std::string path;
	int fd;
	std::filesystem::path* readPath = nullptr;
	std::ofstream* readStream = nullptr;
	std::filesystem::path* writePath = nullptr;
	std::ofstream* writeStream = nullptr;

	PathFD(std::string path, int fd) : path(std::move(path)), fd(fd) {}

	~PathFD() {
		delete readPath;
		delete readStream;
		delete writePath;
		delete writeStream;
	}
};

struct ReadParameters {
	int fd;
	unsigned long long int buffer;
	size_t len;
};

class FileDecoder : public SyscallDecoder {
public:
	static void registerAt(ProcessSyscallDecoderMapper& mapper);
	bool decode(const ProcessSyscallEntry& syscall) override;
	bool decode(const ProcessSyscallExit& syscall) override;
	void printReport() const override;
private:
	static const std::filesystem::path root;
	static const std::set<int> WRITE_SYSCALLS;
	static const std::set<int> READ_SYSCALLS;
	static const std::set<int> OPEN_SYSCALLS;
	static void makeOfstream(int fd, pid_t pid, const std::string& operation, std::filesystem::path** path, std::ofstream** stream);
	std::vector<std::shared_ptr<PathFD>> paths;
	std::map<int, std::shared_ptr<PathFD>> activePaths;
	std::unordered_map<pid_t, std::shared_ptr<PathFD>> awaitingFD;
	std::unordered_map<pid_t, ReadParameters> awaitingRead;
	FileDecoder();
	bool decodeOpenEntry(const ProcessSyscallEntry& syscall);
	bool decodeOpenExit(const ProcessSyscallExit& syscall);
	bool decodeReadEntry(const ProcessSyscallEntry& syscall);
	bool decodeReadExit(const ProcessSyscallExit& syscall);
	bool decodeWrite(const ProcessSyscallEntry& syscall);
};

#endif //PTRACER_FILEDECODER_H
