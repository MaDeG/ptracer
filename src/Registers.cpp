/* 
 * File:   Registers.cpp
 * Author: Matteo De Giorgi
 * 
 * Extension of the ptrace struct user_regs_struct in order to add some easy aliases that
 * facilitate the extraction of commonly used registers.
 */

#include "Registers.h"

using namespace std;

/**
 * Gets the Program Counter (or Instruction Pointer).
 * 
 * @return The Program counter register value.
 */
unsigned long long int Registers::pc() const {
#if defined(ARCH_ARM)
	return user_regs_struct::pc;
#elif defined(ARCH_X86_64)
	return this->rip;
#else
	#error "No supported architecture"
#endif
}

#ifdef ARCH_X86_64
/**
 * Gets the Stack Base Pointer.
 * 
 * @return The Stack Base Pointer register value.
 */
unsigned long long int Registers::bp() const {
  return this->rbp;
}
#endif

/**
 * Gets the Stack Pointer.
 * 
 * @return The Stack Pointer register value.
 */
unsigned long long int Registers::sp() const {
#if defined(ARCH_X86_64)
  return this->rsp;
#elif defined(ARCH_ARM)
	return user_regs_struct::sp;
#else
	#error "No supported architecture"
#endif

}

/**
 * Gets the System Call number.
 * 
 * @return The System Call number register value.
 */
int Registers::nsyscall() const {
#if defined(ARCH_X86_64)
  return (int) this->orig_rax;
#elif defined(ARCH_ARM)
	return this->regs[8];
#else
	#error "No supported architecture"
#endif
}

/**
 * Gets the System Call Return Value.
 * 
 * @param regs The Registers whom System Call Return Value will be extracted.
 * @return The System Call Return Value register value.
 */
long long int Registers::ret_arg() const {
#if defined(ARCH_X86_64)
  return (long long int) this->rax;
#elif defined(ARCH_ARM)
	return this->regs[0];
#else
	#error "No supported architecture"
#endif
}

/**
 * Gets the First Parameter of the System Call.
 * 
 * @return The First Parameter of the System Call register value.
 */
unsigned long long int Registers::arg0() const {
#if defined(ARCH_X86_64)
  return this->rdi;
#elif defined(ARCH_ARM)
	return this->regs[0];
#else
	#error "No supported architecture"
#endif
}

/**
 * Gets the Second Parameter of the System Call.
 * 
 * @return The Second Parameter of the System Call register value.
 */
unsigned long long int Registers::arg1() const {
#if defined(ARCH_X86_64)
  return this->rsi;
#elif defined(ARCH_ARM)
	return this->regs[1];
#else
	#error "No supported architecture"
#endif
}

/**
 * Gets the Third Parameter of the System Call.
 * 
 * @return The Third Parameter of the System Call register value.
 */
unsigned long long int Registers::arg2() const {
#if defined(ARCH_X86_64)
  return this->rdx;
#elif defined(ARCH_ARM)
	return this->regs[2];
#else
	#error "No supported architecture"
#endif
}

/**
 * Gets the Fourth Parameter of the System Call.
 * 
 * @return The Fourth Parameter of the System Call register value.
 */
unsigned long long int Registers::arg3() const {
#if defined(ARCH_X86_64)
  return this->r10;
#elif defined(ARCH_ARM)
	return this->regs[3];
#else
	#error "No supported architecture"
#endif
}

/**
 * Gets the Fifth Parameter of the System Call.
 * 
 * @return The Fifth Parameter of the System Call register value.
 */
unsigned long long int Registers::arg4() const {
#if defined(ARCH_X86_64)
  return this->r8;
#elif defined(ARCH_ARM)
	return this->regs[4];
#else
	#error "No supported architecture"
#endif
}

/**
 * Gets the Sixth Parameter of the System Call.
 * 
 * @return The Sixth Parameter of the System Call register value.
 */
unsigned long long int Registers::arg5() const {
#if defined(ARCH_X86_64)
  return this->r9;
#elif defined(ARCH_ARM)
	return this->regs[5];
#else
	#error "No supported architecture"
#endif
}

#if defined(ARCH_ARM)
unsigned long long int Registers::arg6() const {
	return this->regs[6];
}

unsigned long long int Registers::arg7() const {
	return this->regs[7];
}
#endif

/**
 * Defines the object string conversion.
 * It captures only the most important values.
 * 
 * @return The string representation of this object.
 */
Registers::operator string() const {
  string ris = "Registers = {  ";
  ris += "PC : " + to_string(this->pc()) + "  ";
  ris += "SP : " + to_string(this->sp()) + "  ";
  ris += "RET : " + to_string(this->ret_arg()) + "  }";
  return ris;
}