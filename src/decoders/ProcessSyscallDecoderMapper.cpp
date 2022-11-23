#include <iostream>
#include "ConnectDecoder.h"
#include "OpenDecoder.h"
#include "PtraceDecoder.h"
#include "ReadWriteDecoder.h"
#include "ProcessSyscallDecoderMapper.h"
#include "../SyscallNameResolver.h"

using namespace std;

/**
 * Asks to all the Decoders to register themselves to this instance.
 */
ProcessSyscallDecoderMapper::ProcessSyscallDecoderMapper() {
	ConnectDecoder::registerAt(*this);
	OpenDecoder::registerAt(*this);
	PtraceDecoder::registerAt(*this);
	ReadWriteDecoder::registerAt(*this);
}

/**
 * Registers a new SyscallDecoder for a specific syscall number.
 *
 * @param syscall The number of the syscall that should be delegated to this decoder.
 * @param factory The SyscallDecoder that will be delegated to handle syscall.
 */
bool ProcessSyscallDecoderMapper::registerEntrySyscallDecoder(unsigned int syscall, shared_ptr<SyscallDecoder> decoder) {
	auto it = ProcessSyscallDecoderMapper::entrySyscallDecoders.emplace(syscall, decoder);
	if (!it.second) {
		throw runtime_error("A Syscall Entry Decoder for syscall " + to_string(syscall) + " is already registered");
	}
	ProcessSyscallDecoderMapper::decoders.insert(decoder);
	return true;
}

bool ProcessSyscallDecoderMapper::registerExitSyscallDecoder(unsigned int syscall, std::shared_ptr<SyscallDecoder> decoder) {
	auto it = ProcessSyscallDecoderMapper::exitSyscallDecoders.emplace(syscall, decoder);
	if (!it.second) {
		throw runtime_error("A Syscall Exit Decoder for syscall " + to_string(syscall) + " is already registered");
	}
	ProcessSyscallDecoderMapper::decoders.insert(decoder);
	return true;
}

/**
 * Delegates decoding the received entry syscall to the registered SyscallDecoder (if any).
 *
 * @param syscall The syscall entry that shall be handled.
 * @return True if the syscall has been decoded successfully, False an error occurred.
 */
bool ProcessSyscallDecoderMapper::decode(const ProcessSyscallEntry& syscall) {
	auto decoderIt = ProcessSyscallDecoderMapper::entrySyscallDecoders.find(syscall.getSyscall());
	if (decoderIt == ProcessSyscallDecoderMapper::entrySyscallDecoders.end()) {
		return false;
	}
	return decoderIt->second->decode(syscall);
}

/**
 * Delegates decoding the received exit syscall to the registered SyscallDecoder (if any).
 *
 * @param syscall The syscall exit that shall be handled.
 * @return True if the syscall has been decoded successfully, False an error occurred.
 */
bool ProcessSyscallDecoderMapper::decode(const ProcessSyscallExit& syscall) {
	auto decoderIt = ProcessSyscallDecoderMapper::exitSyscallDecoders.find(syscall.getSyscall());
	if (decoderIt == ProcessSyscallDecoderMapper::exitSyscallDecoders.end()) {
		return false;
	}
	return decoderIt->second->decode(syscall);
}

/**
 * Iterates over all the registered syscalls decoders and prints a report for each of those.
 */
void ProcessSyscallDecoderMapper::printReport() const {
	for (auto& syscall : this->decoders) {
		syscall->printReport();
	}
}