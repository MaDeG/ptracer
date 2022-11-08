#include <assert.h>
#include <iostream>
#include <string.h>
#include "BacktracerImpl.h"

using namespace std;

const unsigned int BacktracerImpl::MAX_FRAMES = 1024;
const unsigned int BacktracerImpl::MAX_FUNCTION_NAME_LENGTH = 256;

BacktracerImpl::BacktracerImpl() : Backtracer() {
	this->_address_space = unw_create_addr_space(&_UPT_accessors, 0);
}

void BacktracerImpl::init(pid_t pid) {
	assert(pid >= 0);
	this->_info = (UPT_info*) _UPT_create(pid);
	if (this->_address_space == nullptr && (this->_address_space = unw_create_addr_space(&_UPT_accessors, 0)) == nullptr) {
		throw new runtime_error("Error while initialising the libunwind address space");
	}
	if (this->_info == nullptr && (this->_info = (UPT_info*) _UPT_create(pid)) == nullptr) {
		throw new runtime_error("Error during libunwind initialization");
	}
}

std::vector<StackFrame> BacktracerImpl::unwind() {
	vector<StackFrame> frames;
	unw_cursor_t it;
	unw_word_t sp, offset, pc;
	char functionName[BacktracerImpl::MAX_FUNCTION_NAME_LENGTH];
	if (unw_init_remote(&it, this->_address_space, this->_info)) {
		throw new runtime_error("Error during the remote cursor initialization for remote unwinding");
	}


//	if (unw_get_reg(&it, UNW_REG_IP, &pc) != UNW_ESUCCESS) {
//		throw new runtime_error("Error during call backtrace retrieval: impossible to retrieve the instruction pointer");
//	}
	/*TODO: Move this up?
	 * if (pc != this->_current_state->regs_state->pc()) {
		cout << "Expected program counter: " << this->_current_state->regs_state->pc() << endl;
		cout << "Retrieved by libunwind: " << pc << endl;
		if ((long long int) (this->_pc_base_addr - pc) < 0) {
			cout << "Detected a libunwind problem, the expected value will be used" << endl;
		} else {
			cout << "Error! Both program counters may be valid, abort!" << endl;
			return Tracer::UNWIND_ERROR;
		}
	}*/
//	if (unw_get_reg(&it, UNW_REG_SP, &sp) != UNW_ESUCCESS) {
//		throw new runtime_error("Error during call backtrace retrieval: impossible to retrieve a stack pointer");
//	}
	/*assert(sp == this->_current_state->regs_state->sp());
	if (!this->_sp_base_addr) {
		this->_sp_base_addr = sp;
	}
	if (this->_no_backtrace) {
		this->_current_state->sp_backtrace.push_back((long long int) (this->_sp_base_addr - sp));
	}*/

	do {
		functionName[0] = '\0';
		if (unw_get_reg(&it, UNW_REG_IP, &pc) != UNW_ESUCCESS) {
			throw new runtime_error("Error during call backtrace retrieval: impossible to retrieve the instruction pointer");
		}
		if (unw_get_reg(&it, UNW_REG_SP, &sp) != UNW_ESUCCESS) {
			throw new runtime_error("Error during call backtrace retrieval: impossible to retrieve a stack pointer");
		}
		if (unw_get_proc_name(&it, functionName, BacktracerImpl::MAX_FUNCTION_NAME_LENGTH, &offset) != UNW_ESUCCESS) {
			cerr << "Error during call backtrace retrieval: impossible to retrieve a function name" << endl;
			sprintf(functionName, "%#016x", pc);
		}
		//this->_current_state->pc_backtrace.push_back((long long int) (this->_pc_base_addr - pc));

		//TODO: What should be relative PC?
		frames.emplace_back(pc, 0, sp, string(functionName), offset);

		//cout << function_name << " + " << offset << " @ " << pc << " SP: " << sp << endl;
	} while (unw_step(&it) > 0 && frames.size() < BacktracerImpl::MAX_FRAMES);
	return frames;
}

BacktracerImpl::~BacktracerImpl() {
	if (this->_address_space != nullptr) {
		unw_destroy_addr_space(this->_address_space);
	}
	if (this->_info != nullptr) {
		_UPT_destroy(this->_info);
	}
}