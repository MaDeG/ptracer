#include <assert.h>
#include <iostream>
#include <sys/syscall.h>
#include "ExecveDecoder.h"
#include "../Tracer.h"

using namespace std;

bool ExecveDecoder::decode(const ProcessSyscallEntry& syscall) {
	// TODO: in execveat pathname can be null, flags must be checked
	assert(syscall.getSyscall() == SYS_execve || syscall.getSyscall() == SYS_execveat);
	unsigned long long pathPtr = syscall.getSyscall() == SYS_execve ? syscall.argument(0) : syscall.argument(1);
	unsigned long long argvPtr = syscall.getSyscall() == SYS_execve ? syscall.argument(1) : syscall.argument(2);
	string path = syscall.getTracer()->extractString(pathPtr, Tracer::MAXIMUM_PROCESS_NAME_LENGTH);
	unsigned long long* argv = (unsigned long long*) syscall.getTracer()->extractBytes(argvPtr, 80); // 10 pointers of 8 bytes each
	vector<string> args;
	unsigned long long* it = argv;
	while (*it) {
		args.push_back(syscall.getTracer()->extractString((unsigned long long) *it, Tracer::MAXIMUM_PROCESS_NAME_LENGTH));
		it++;
	}
	this->executables.emplace_back((ExecCall) {path, args});
	delete[] argv;
	return true;
}

bool ExecveDecoder::decode(const ProcessSyscallExit& syscall) {
	return true;
}

void ExecveDecoder::registerAt(ProcessSyscallDecoderMapper& mapper) {
	shared_ptr<SyscallDecoder> thisDecoder(new ExecveDecoder());
	mapper.registerEntrySyscallDecoder(SYS_execve, thisDecoder);
	mapper.registerEntrySyscallDecoder(SYS_execveat, thisDecoder);
}

void ExecveDecoder::printReport() const {
	cout << "------------------ EXECVE DECODER START ------------------" << endl;
	for (const ExecCall& call : this->executables) {
		cout << "Executable: " << call.path << endl;
		cout << "Arguments: " << endl;
		for (int i = 0; i < call.argv.size(); i++) {
			cout << "[" << i << "] = " << call.argv.at(i) << endl;
		}
	}
	cout << "------------------ EXECVE DECODER STOP -------------------" << endl;
}