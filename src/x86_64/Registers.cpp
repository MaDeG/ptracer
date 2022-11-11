/* 
 * File:   Registers.cpp
 * Author: Matteo De Giorgi
 * 
 * Extension of the ptrace struct user_regs_struct in order to add some easy aliases that
 * facilitate the extraction of commonly used registers.
 */
#include <stdexcept>
#include "../Registers.h"

using namespace std;

/**
 * The number of syscall arguments available for this architecture.
 */
const unsigned short int Registers::ARGS_COUNT = 6;

/**
 * Constructor initializes the iovec structure since this class will always be used in
 * conjunction with ptrace GETREGSET which requires that data structure.
 */
Registers::Registers() : io({(user_regs_struct*) this, sizeof(user_regs_struct)}) { }

/**
 * Gets the Program Counter (or Instruction Pointer).
 * 
 * @return The Program counter register value.
 */
unsigned long long int Registers::pc() const {
	return this->rip;
}

/**
 * Gets the Stack Base Pointer.
 * 
 * @return The Stack Base Pointer register value.
 */
unsigned long long int Registers::bp() const {
  return this->rbp;
}

/**
 * Gets the Stack Pointer.
 * 
 * @return The Stack Pointer register value.
 */
unsigned long long int Registers::sp() const {
  return this->rsp;
}

/**
 * Gets the System Call number.
 * 
 * @return The System Call number register value.
 */
unsigned int Registers::syscall() const {
  return (int) this->orig_rax;
}

/**
 * Gets the System Call Return Value.
 * 
 * @param regs The Registers whom System Call Return Value will be extracted.
 * @return The System Call Return Value register value.
 */
long long int Registers::returnValue() const {
  return (long long int) this->rax;
}

/**
 * Gets the N-th Parameter of the System Call.
 * 
 * @return The N-th Parameter of the System Call register value.
 */
unsigned long long int Registers::argument(unsigned short int i) const {
	switch (i) {
		case 0:
			return this->rdi;
		case 1:
			return this->rsi;
		case 2:
			return this->rdx;
		case 3:
			return this->r10;
		case 4:
			return this->r8;
		case 5:
			return this->r9;
		default:
			throw runtime_error("The requested argument does not exists, only 6 (range 0-5) available");
	}
}

/**
 * Gets the CPU flags at the time of this system call, check the architecture ABI for more details.
 *
 * @return The CPU flags at the time of this system call.
 */
unsigned long long int Registers::flags() const {
	return this->eflags;
}