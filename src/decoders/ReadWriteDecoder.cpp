#include <assert.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sys/syscall.h>
#include "ReadWriteDecoder.h"
#include "../Tracer.h"

using namespace std;

const filesystem::path ReadWriteDecoder::root{"./ReadWriteDecoder"};

const set<int> ReadWriteDecoder::WRITE_SYSCALLS = {SYS_write,
																									 // SYS_sendmsg,
																									 // SYS_sendmmsg, Need to interpret const struct msghdr* msg
																									 // SYS_preadv
																									 SYS_sendto,
																									 SYS_pread64,
#ifdef SYS_send
																							     SYS_send
#endif
};

const set<int> ReadWriteDecoder::READ_SYSCALLS = {SYS_read,
																								  SYS_recvfrom,
	                                                SYS_recvmsg,
	                                                SYS_recvmmsg
#ifdef SYS_recv
																							    SYS_recv
#endif
};

bool ReadWriteDecoder::decode(const ProcessSyscallEntry& syscall) {
	ofstream* out;
	if (ReadWriteDecoder::isWrite(syscall.getSyscall())) {
		out = ReadWriteDecoder::getOfstream(syscall, this->writeOutputs, "-write");
	} else {
		out = ReadWriteDecoder::getOfstream(syscall, this->readOutputs, "-read");
	}
	assert(out->is_open());
	// TODO: Validate those parameters, what if they are corrupted?
	if (syscall.argument(2) <= 0) {
		cerr << "Found potentially corrupted syscall parameters, read/write parameters will not be checked" << endl;
		return false;
	}
	char* extracted = (char*) syscall.getTracer()->extractBytes(syscall.argument(1), syscall.argument(2));
	if (!extracted) {
		return false;
	}
	out->write(extracted, syscall.argument(2));
	out->flush();
	delete[] extracted;
	return true;
}

/**
 * This decoder does not handle exit syscall notifications.
 *
 * @param syscall The exit syscall notification
 * @return Always true.
 */
bool ReadWriteDecoder::decode(const ProcessSyscallExit& syscall) {
	return true;
}

ofstream* ReadWriteDecoder::getOfstream(const ProcessSyscallEntry& syscall, map<int, OutFile>& map, string append) {
	ofstream* out;
	auto it = map.find(syscall.argument(0));
	if (it == map.end()) {
		filesystem::path pidRoot(ReadWriteDecoder::root / to_string(syscall.getPid()));
		filesystem::create_directory(pidRoot);
		// All file descriptors are unique per process per execution
		filesystem::path path(pidRoot / (to_string(syscall.argument(0)) + append));
		auto pair = map.emplace((int) syscall.argument(0), (OutFile) {path, ofstream(path, ios::out | ios::binary)});
		out = &pair.first->second.outStream;
	} else {
		out = &it->second.outStream;
	}
	return out;
}

void ReadWriteDecoder::registerAt(ProcessSyscallDecoderMapper& mapper) {
	if (!filesystem::is_directory(root)) {
		filesystem::create_directory(root);
	}
	shared_ptr<SyscallDecoder> thisDecoder(new ReadWriteDecoder());
	for (int syscall : ReadWriteDecoder::WRITE_SYSCALLS) {
		mapper.registerEntrySyscallDecoder(syscall, thisDecoder);
	}
	for (int syscall : ReadWriteDecoder::READ_SYSCALLS) {
		mapper.registerEntrySyscallDecoder(syscall, thisDecoder);
	}
}

/**
 * Prints a report of all the read and write content files saved.
 */
void ReadWriteDecoder::printReport() const {
	cout << "------------------ READ DECODER START ------------------" << endl;
	for (auto& i : this->readOutputs) {
		cout << "File Descriptor " << i.first << " read content extracted in: " << i.second.path << ", bytes: " << filesystem::file_size(i.second.path) << endl;
	}
	cout << "------------------ READ DECODER END ------------------" << endl;
	cout << "------------------ WRITE DECODER START ------------------" << endl;
	for (auto& i : this->writeOutputs) {
		cout << "File Descriptor " << i.first << " written content extracted in: " << i.second.path << ", bytes: " << filesystem::file_size(i.second.path) << endl;
	}
	cout << "------------------ WRITE DECODER END ------------------" << endl;
}

bool ReadWriteDecoder::isWrite(int syscall) {
	if (ReadWriteDecoder::WRITE_SYSCALLS.find(syscall) != ReadWriteDecoder::WRITE_SYSCALLS.end()) {
		return true;
	}
	assert(ReadWriteDecoder::READ_SYSCALLS.find(syscall) != ReadWriteDecoder::READ_SYSCALLS.end());
	return false;
}