#include <cassert>
#include <chrono>
#include <cstring>
#include <iostream>
#include <sys/syscall.h>
#include "FileDecoder.h"
#include "../Tracer.h"

using namespace std;

const filesystem::path FileDecoder::root{"./FileDecoder"};

//TODO: sendfile

const set<int> FileDecoder::READ_SYSCALLS = {SYS_read,
                                             SYS_recvfrom,
																						 SYS_pread64,
                                             // SYS_recvmsg, TODO: Need to interpret msghdr*
                                             // SYS_recvmmsg, TODO: Need to interpret mmsghdr*
#ifdef SYS_recv
																						 SYS_recv
#endif
};

const set<int> FileDecoder::WRITE_SYSCALLS = {SYS_write,
// TODO: SYS_sendmsg,
// TODO: SYS_sendmmsg, Need to interpret const struct msghdr* msg
// TODO: SYS_pwritev, SYS_pwritev2
		                                          SYS_sendto,
		                                          SYS_pwrite64,
#ifdef SYS_send
																							SYS_send
#endif
};

const set<int> FileDecoder::OPEN_SYSCALLS = {SYS_openat,
																						 SYS_openat2,
																						 SYS_name_to_handle_at,
#ifdef SYS_creat
																						 SYS_creat,
#endif
// TODO: Missing open_by_handle_at
// TODO: Implement dup, dup2 and dup3
// TODO: Implement pipe for redirections
#ifdef SYS_open
																						 SYS_open,
#endif
};

void FileDecoder::registerAt(ProcessSyscallDecoderMapper& mapper) {
	if (!filesystem::is_directory(root)) {
		filesystem::create_directory(root);
	}
	shared_ptr<SyscallDecoder> thisDecoder(new FileDecoder());
	for (int syscall : FileDecoder::READ_SYSCALLS) {
		// It is necessary to first save the buffer address and then read it when the syscall will be completed
		mapper.registerEntrySyscallDecoder(syscall, thisDecoder);
		mapper.registerExitSyscallDecoder(syscall, thisDecoder);
	}
	for (int syscall : FileDecoder::WRITE_SYSCALLS) {
		mapper.registerEntrySyscallDecoder(syscall, thisDecoder);
	}
	for (int syscall : FileDecoder::OPEN_SYSCALLS) {
		mapper.registerEntrySyscallDecoder(syscall, thisDecoder);
		mapper.registerExitSyscallDecoder(syscall, thisDecoder);
	}
	//TODO: Also mmap can be used to read a file
}

bool FileDecoder::decode(const ProcessSyscallEntry& syscall) {
	if (FileDecoder::READ_SYSCALLS.find(syscall.getSyscall()) != FileDecoder::READ_SYSCALLS.end()) {
		return this->decodeReadEntry(syscall);
	} else if (FileDecoder::WRITE_SYSCALLS.find(syscall.getSyscall()) != FileDecoder::WRITE_SYSCALLS.end()) {
		return this->decodeWrite(syscall);
	} else {
		assert(FileDecoder::OPEN_SYSCALLS.find(syscall.getSyscall()) != FileDecoder::OPEN_SYSCALLS.end());
		return this->decodeOpenEntry(syscall);
	}
}

bool FileDecoder::decode(const ProcessSyscallExit& syscall) {
	if (FileDecoder::READ_SYSCALLS.find(syscall.getSyscall()) != FileDecoder::READ_SYSCALLS.end()) {
		return this->decodeReadExit(syscall);
	} else {
		assert(FileDecoder::OPEN_SYSCALLS.find(syscall.getSyscall()) != FileDecoder::OPEN_SYSCALLS.end());
		return this->decodeOpenExit(syscall);
	}
}

/**
 * Prints a report of all the opened paths observed.
 */
void FileDecoder::printReport() const {
	cout << "------------------ FILE DECODER START ------------------" << endl;
	for (const shared_ptr<PathFD>& pathFd : this->paths) {
		if (pathFd->fd >= 0) {
			cout << "File Descriptor: " << pathFd->fd << " <---> " << pathFd->path << endl;
			if (pathFd->readStream != nullptr) {
				cout << "Read content extracted in: " << *pathFd->readPath << ", bytes: " << filesystem::file_size(*pathFd->readPath) << endl;
			}
			if (pathFd->writeStream != nullptr) {
				cout << "Write content extracted in: " << *pathFd->writePath << ", bytes: " << filesystem::file_size(*pathFd->writePath) << endl;
			}
		} else {
			cout << "Attempt to open path: " << pathFd->path << " failed with error: " << pathFd->fd << ", " << strerror(-pathFd->fd) << endl;
		}
	}
	cout << "------------------ FILE DECODER STOP ------------------" << endl;
}

FileDecoder::FileDecoder() {
	// Pre-create entries for STDIN, STDOUT and STDERR
	shared_ptr<PathFD> path;
	path = this->paths.emplace_back(make_shared<PathFD>("STDIN", 0));
	this->activePaths[0] = path;
	path = this->paths.emplace_back(make_shared<PathFD>("STDOUT", 1));
	this->activePaths[1] = path;
	path = this->paths.emplace_back(make_shared<PathFD>("STDERR", 2));
	this->activePaths[2] = path;
}

void FileDecoder::makeOfstream(int fd, pid_t pid, const string& operation, filesystem::path** path, ofstream** stream) {
	filesystem::path pidRoot(FileDecoder::root / to_string(pid));
	filesystem::create_directory(pidRoot);
	// All file descriptors are unique per process per execution, but once closed can be reused
	string timestamp = to_string(duration_cast<chrono::milliseconds>(chrono::system_clock::now().time_since_epoch()).count());
	*path = new filesystem::path(pidRoot / (to_string(fd) + "-" + operation + "-" + timestamp));
	*stream = new ofstream(**path, ios::out | ios::binary);
}

bool FileDecoder::decodeOpenEntry(const ProcessSyscallEntry& syscall) {
	string path = syscall.getTracer()->extractString(syscall.argument(1), 2048);
	shared_ptr<PathFD> pathFD = this->paths.emplace_back(make_shared<PathFD>(move(path), -1));
	this->awaitingFD[syscall.getSpid()] = pathFD;
	return true;
}

bool FileDecoder::decodeOpenExit(const ProcessSyscallExit& syscall) {
	auto it = this->awaitingFD.find(syscall.getSpid());
	if (it == this->awaitingFD.end()) {
		cerr << "Received a syscall exit that does not match any open syscall entry!" << endl;
		return false;
	}
	shared_ptr<PathFD> path = it->second;
	path->fd = syscall.getReturnValue();
	if (path->fd >= 0) {
		this->activePaths[path->fd] = path;
	}
	this->awaitingFD.erase(it);
	return true;
}

bool FileDecoder::decodeReadEntry(const ProcessSyscallEntry& syscall) {
	this->awaitingRead[syscall.getSpid()] = (ReadParameters) {static_cast<int>(syscall.argument(0)), syscall.argument(1), syscall.argument(2)};
	return true;
}

bool FileDecoder::decodeReadExit(const ProcessSyscallExit& syscall) {
	ssize_t returnValue = syscall.getReturnValue();
	auto parametersIt = this->awaitingRead.find(syscall.getSpid());
	if (parametersIt == this->awaitingRead.end()) {
		cerr << "Cannot find a matching system call entry for the received read system call!" << endl;
		return false;
	}
	ReadParameters readParameters = parametersIt->second;
	this->awaitingRead.erase(parametersIt);
	if (returnValue < 0 || readParameters.len <= 0) {
		// TODO: It should be reported, for now ignore
		return true;
	}
	auto it = this->activePaths.find(readParameters.fd);
	shared_ptr<PathFD> path;
	if (it == this->activePaths.end()) {
		// This FD does not correspond with a file
		// TODO: Better integrate this with sockets
		path = this->paths.emplace_back(make_shared<PathFD>("socket-" + to_string(readParameters.fd), readParameters.fd));
		this->activePaths[path->fd] = path;
	} else {
		path = it->second;
	}
	if (path->readStream == nullptr) {
		this->makeOfstream(readParameters.fd, syscall.getPid(), "read", &path->readPath, &path->readStream);
	}
	// The system call will return the number of read bytes or 0 if the buffer has been filled
	ssize_t len = returnValue ? returnValue : readParameters.len;
	char* extracted = (char*) (syscall.getTracer()->extractBytes(readParameters.buffer, len));
	if (!extracted) {
		return false;
	}
	path->readStream->write(extracted, len);
	path->readStream->flush();
	delete[] extracted;
	return true;
}

//TODO: read and write are too similar -> unify in one parametrized function
bool FileDecoder::decodeWrite(const ProcessSyscallEntry& syscall) {
	auto it = this->activePaths.find(syscall.argument(0));
	shared_ptr<PathFD> path;
	if (it == this->activePaths.end()) {
		// This FD does not correspond with a file
		// TODO: Better integrate this with sockets
		path = this->paths.emplace_back(make_shared<PathFD>("socket-" + to_string(syscall.argument(0)), syscall.argument(0)));
		this->activePaths[path->fd] = path;
	} else {
		path = it->second;
	}
	if (path->writeStream == nullptr) {
		this->makeOfstream(syscall.argument(0), syscall.getPid(), "write", &path->writePath, &path->writeStream);
	}
	char* extracted = (char*) (syscall.getTracer()->extractBytes(syscall.argument(1), syscall.argument(2)));
	if (!extracted) {
		return false;
	}
	path->writeStream->write(extracted, syscall.argument(2));
	path->writeStream->flush();
	delete[] extracted;
	return true;
}