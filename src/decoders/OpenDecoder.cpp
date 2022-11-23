#include <iostream>
#include <sys/syscall.h>
#include "OpenDecoder.h"
#include <sys/ioctl.h>

using namespace std;

bool OpenDecoder::decode(const ProcessSyscallEntry& syscall) {
	string path = syscall.getTracer()->extractString(syscall.argument(1), 2048);
	cout << "Open Decoder - Opened path: " << path << endl;
	PathFD& pathFD = this->paths.emplace_back((PathFD) {move(path), -1});
	this->awaitingFD[syscall.getSpid()] = &pathFD;
	return true;
}

bool OpenDecoder::decode(const ProcessSyscallExit& syscall) {
	auto node = this->awaitingFD.extract(syscall.getSpid());
	if (node.empty()) {
		cerr << "Received a syscall exit that does not match any open syscall entry!" << endl;
		return false;
	}
	node.mapped()->fd = syscall.getReturnValue();
	return true;
}

void OpenDecoder::registerAt(ProcessSyscallDecoderMapper& mapper) {
	shared_ptr<SyscallDecoder> thisDecoder(new OpenDecoder());
	mapper.registerEntrySyscallDecoder(SYS_openat, thisDecoder);
	mapper.registerExitSyscallDecoder(SYS_openat, thisDecoder);
	mapper.registerEntrySyscallDecoder(SYS_openat2, thisDecoder);
	mapper.registerExitSyscallDecoder(SYS_openat2, thisDecoder);
	mapper.registerEntrySyscallDecoder(SYS_name_to_handle_at, thisDecoder);
	mapper.registerExitSyscallDecoder(SYS_name_to_handle_at, thisDecoder);
	// TODO: Missing open_by_handle_at
#ifdef SYS_open
	mapper.registerEntrySyscallDecoder(SYS_open, thisDecoder);
	mapper.registerExitSyscallDecoder(SYS_open, thisDecoder);
#endif
}

/**
 * Prints a report of all the opened paths observed.
 */
void OpenDecoder::printReport() const {
	cout << "------------------ OPEN DECODER START ------------------" << endl;
	for (const PathFD& pathFd : this->paths) {
		if (pathFd.fd >= 0) {
			cout << "File Descriptor: " << pathFd.fd << " <--->" << pathFd.path << endl;
		} else {
			cout << "Attempt to open path: " << pathFd.path << " failed with error: " << pathFd.fd << endl;
		}
	}
	cout << "------------------ OPEN DECODER STOP ------------------" << endl;
}