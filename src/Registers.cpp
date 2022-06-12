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
int Registers::nsyscall() const {
  return (int) this->orig_rax;
}

/**
 * Gets the System Call Return Value.
 * 
 * @param regs The Registers whom System Call Return Value will be extracted.
 * @return The System Call Return Value register value.
 */
long long int Registers::ret_arg() const {
  return (long long int) this->rax;
}

/**
 * Gets the First Parameter of the System Call.
 * 
 * @return The First Parameter of the System Call register value.
 */
unsigned long long int Registers::arg0() const {
  return this->rdi;
}

/**
 * Gets the Second Parameter of the System Call.
 * 
 * @return The Second Parameter of the System Call register value.
 */
unsigned long long int Registers::arg1() const {
  return this->rsi;
}

/**
 * Gets the Third Parameter of the System Call.
 * 
 * @return The Third Parameter of the System Call register value.
 */
unsigned long long int Registers::arg2() const {
  return this->rdx;
}

/**
 * Gets the Fourth Parameter of the System Call.
 * 
 * @return The Fourth Parameter of the System Call register value.
 */
unsigned long long int Registers::arg3() const {
  return this->r10;
}

/**
 * Gets the Fifth Parameter of the System Call.
 * 
 * @return The Fifth Parameter of the System Call register value.
 */
unsigned long long int Registers::arg4() const {
  return this->r8;
}

/**
 * Gets the Sixth Parameter of the System Call.
 * 
 * @return The Sixth Parameter of the System Call register value.
 */
unsigned long long int Registers::arg5() const {
  return this->r9;
}

/**
 * Defines the object string conversion.
 * It captures only the most important values.
 * 
 * @return The string representation of this object.
 */
Registers::operator string() const {
  string ris = "Registers = {  ";
  ris += "PC : " + to_string(this->pc()) + "  ";
  ris += "BP : " + to_string(this->bp()) + "  ";
  ris += "RET : " + to_string(this->ret_arg()) + "  }";
  return ris;
}