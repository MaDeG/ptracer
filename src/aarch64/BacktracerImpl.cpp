#include <cxxabi.h>
#include <iostream>
#include "BacktracerImpl.h"

using namespace unwindstack;
using namespace std;

const unsigned int BacktracerImpl::MAX_FRAMES = 1024;

void BacktracerImpl::init(pid_t pid) {
	this->unwinder = make_unique<UnwinderFromPid>(BacktracerImpl::MAX_FRAMES, pid, ArchEnum::ARCH_ARM64);
	this->pid = pid;
}

std::vector<StackFrame> BacktracerImpl::unwind() {
	std::vector<StackFrame> frames;
	Regs* regs = Regs::RemoteGet(this->pid);
	if (regs == nullptr) {
		cerr << "Unable to get remote registers data" << endl;
		return frames;
	}
	this->unwinder->SetRegs(regs);
	this->unwinder->Unwind();
//	for (int i = 0; i < this->unwinder->NumFrames(); i++) {
//		cout << this->unwinder->FormatFrame(i) << endl;
//	}
	for (FrameData& i : unwinder->ConsumeFrames()) {
		string functionName = (string) i.function_name;
		char* demangled_name = abi::__cxa_demangle(i.function_name.c_str(), nullptr, nullptr, nullptr);
		if (demangled_name != nullptr) {
			functionName = string(demangled_name);
			free(demangled_name);
		}
		frames.emplace_back(i.pc, i.rel_pc, i.sp, functionName, i.function_offset);
	}
	return frames;
}
