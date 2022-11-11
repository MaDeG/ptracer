/* 
 * File:   Registers.cpp
 * Author: Matteo De Giorgi
 * 
 * Extension of the ptrace struct user_regs_struct in order to add some easy aliases that
 * facilitate the extraction of commonly used registers.
 */

#include "../Registers.h"

using namespace std;

/**
 * The number of syscall arguments available for this architecture.
 */
const unsigned short int Registers::ARGS_COUNT = 8;

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
	return user_regs_struct::pc;
}

/**
 * Gets the Stack Pointer.
 * 
 * @return The Stack Pointer register value.
 */
unsigned long long int Registers::sp() const {
	return user_regs_struct::sp;

}

/**
 * Gets the System Call number.
 * 
 * @return The System Call number register value.
 */
unsigned int Registers::syscall() const {
	return this->regs[8];
}

/**
 * Gets the System Call Return Value.
 * 
 * @param regs The Registers whom System Call Return Value will be extracted.
 * @return The System Call Return Value register value.
 */
long long int Registers::returnValue() const {
	return this->regs[0];
}

/**
 * Gets the N-th Parameter of the System Call.
 *
 * @return The N-th Parameter of the System Call.
 */
unsigned long long int Registers::argument(unsigned short int i) const {
	if (i > 7) {
		throw runtime_error("The requested argument does not exists, only 8 (range 0-7) available");
	}
	return this->regs[i];
}

/**
 * Gets the CPU flags at the time of this system call, check the architecture ABI for more details.
 *
 * @return The CPU flags at the time of this system call.
 */
unsigned long long int Registers::flags() const {
	return this->pstate;
}