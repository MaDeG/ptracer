#include <iostream>
#include "SyscallDecoderMapper.h"

using namespace std;

map<pid_t, ProcessSyscallDecoderMapper> SyscallDecoderMapper::decoders;

/**
 * Delegates decoding a system call entry to one of the SyscallDecoders registered in the map.
 *
 * @param syscall The syscall that needs to be decoded.
 * @return The result of decoding the syscall or False if any error occurred.
 */
bool SyscallDecoderMapper::decode(const ProcessSyscallEntry& syscall) {
	if (!SyscallDecoderMapper::enabled) {
		// TODO: Improve this
		return true;
	}
	return SyscallDecoderMapper::decoders[syscall.getPid()].decode(syscall);
}

/**
 * Delegates decoding a system call exit to one of the SyscallDecoders registered in the map.
 *
 * @param syscall The syscall exit that needs to be decoded.
 * @return The result of decoding the syscall or False if any error occurred.
 */
bool SyscallDecoderMapper::decode(const ProcessSyscallExit& syscall) {
	if (!SyscallDecoderMapper::enabled) {
		return true;
	}
	return SyscallDecoderMapper::decoders[syscall.getPid()].decode(syscall);
}

/**
 * Iterates over all the saved PIDs and prints a report for each of those.
 */
void SyscallDecoderMapper::printReport() {
	if (!SyscallDecoderMapper::enabled) {
		return;
	}
	cout << "------------------ SYSCALL DECODERS REPORT START ------------------" << endl;
	for (auto process : SyscallDecoderMapper::decoders) {
		cout << "------------------ PID " << process.first << " START ------------------" << endl;
		process.second.printReport();
		cout << "------------------ PID " << process.first << " STOP ------------------" << endl;
	}
	cout << "------------------ SYSCALL DECODERS REPORT STOP ------------------" << endl;
}
