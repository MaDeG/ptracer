#include <iostream>
#include <linux/ptrace.h>
#include <sys/syscall.h>
#include "PtraceDecoder.h"

using namespace std;

unordered_map<int, string> PtraceDecoder::ptraceCommands;

bool PtraceDecoder::decode(const ProcessSyscallEntry& syscall) {
	this->ptraceCalls.push_back({(int) syscall.argument(0), (pid_t) syscall.argument(1)});
	return true;
}

/**
 * This decoder does not handle exit syscall notifications.
 *
 * @param syscall The exit syscall notification
 * @return Always true.
 */
bool PtraceDecoder::decode(const ProcessSyscallExit& syscall) {
	return true;
}

void PtraceDecoder::registerAt(ProcessSyscallDecoderMapper& mapper) {
	if (PtraceDecoder::ptraceCommands.empty()) {
		PtraceDecoder::initCommands();
	}
	shared_ptr<SyscallDecoder> thisDecoder(new PtraceDecoder());
	mapper.registerEntrySyscallDecoder(SYS_ptrace, thisDecoder);
}

/**
 * Prints a report of all the opened paths observed.
 */
void PtraceDecoder::printReport() const {
	cout << "------------------ PTRACE DECODER START ------------------" << endl;
	for (const PtraceCall& call : this->ptraceCalls) {
		cout << "Command: " << PtraceDecoder::ptraceCommands[call.command] << " on PID: " << call.targetPid << endl;
	}
	cout << "------------------ PTRACE DECODER START ------------------" << endl;
}

void PtraceDecoder::initCommands() {
	PtraceDecoder::ptraceCommands[PTRACE_TRACEME] = "PTRACE_TRACEME";
	PtraceDecoder::ptraceCommands[PTRACE_PEEKTEXT] = "PTRACE_PEEKTEXT";
	PtraceDecoder::ptraceCommands[PTRACE_PEEKDATA] = "PTRACE_PEEKDATA";
	PtraceDecoder::ptraceCommands[PTRACE_PEEKUSR] = "PTRACE_PEEKUSR";
	PtraceDecoder::ptraceCommands[PTRACE_POKETEXT] = "PTRACE_POKETEXT";
	PtraceDecoder::ptraceCommands[PTRACE_POKEDATA] = "PTRACE_POKEDATA";
	PtraceDecoder::ptraceCommands[PTRACE_POKEUSR] = "PTRACE_POKEUSR";
	PtraceDecoder::ptraceCommands[PTRACE_CONT] = "PTRACE_CONT";
	PtraceDecoder::ptraceCommands[PTRACE_KILL] = "PTRACE_KILL";
	PtraceDecoder::ptraceCommands[PTRACE_SINGLESTEP] = "PTRACE_SINGLESTEP";
	PtraceDecoder::ptraceCommands[PTRACE_ATTACH] = "PTRACE_ATTACH";
	PtraceDecoder::ptraceCommands[PTRACE_DETACH] = "PTRACE_DETACH";
	PtraceDecoder::ptraceCommands[PTRACE_SYSCALL] =	"PTRACE_SYSCALL";
	PtraceDecoder::ptraceCommands[PTRACE_SETOPTIONS] = "PTRACE_SETOPTIONS";
	PtraceDecoder::ptraceCommands[PTRACE_GETEVENTMSG] = "PTRACE_GETEVENTMSG";
	PtraceDecoder::ptraceCommands[PTRACE_GETSIGINFO] = "PTRACE_GETSIGINFO";
	PtraceDecoder::ptraceCommands[PTRACE_SETSIGINFO] = "PTRACE_SETSIGINFO";
	PtraceDecoder::ptraceCommands[PTRACE_GETREGSET] = "PTRACE_GETREGSET";
	PtraceDecoder::ptraceCommands[PTRACE_SETREGSET] = "PTRACE_SETREGSET";
	PtraceDecoder::ptraceCommands[PTRACE_SEIZE] = "PTRACE_SEIZE";
	PtraceDecoder::ptraceCommands[PTRACE_INTERRUPT] = "PTRACE_INTERRUPT";
	PtraceDecoder::ptraceCommands[PTRACE_LISTEN] = "PTRACE_LISTEN";
	PtraceDecoder::ptraceCommands[PTRACE_PEEKSIGINFO] = "PTRACE_PEEKSIGINFO";
	PtraceDecoder::ptraceCommands[PTRACE_GETSIGMASK] = "PTRACE_GETSIGMASK";
	PtraceDecoder::ptraceCommands[PTRACE_SETSIGMASK] = "PTRACE_SETSIGMASK";
	PtraceDecoder::ptraceCommands[PTRACE_SECCOMP_GET_FILTER] = "PTRACE_SECCOMP_GET_FILTER";
	PtraceDecoder::ptraceCommands[PTRACE_SECCOMP_GET_METADATA] = "PTRACE_SECCOMP_GET_METADATA";
	PtraceDecoder::ptraceCommands[PTRACE_GET_SYSCALL_INFO] = "PTRACE_GET_SYSCALL_INFO";
}