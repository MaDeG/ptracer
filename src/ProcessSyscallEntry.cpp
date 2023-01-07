#include <vector>
#include <iostream>
#include <sys/syscall.h>
#include <boost/format.hpp>
#include "Tracer.h"
#include "ProcessSyscallEntry.h"
#include "TracingManager.h"
#include "SyscallNameResolver.h"

using namespace std;

// Set of System call numbers that may generate a child
const set<int> ProcessSyscallEntry::childGeneratingSyscalls = { SYS_clone,
#ifdef ARCH_X8664
																															  SYS_fork,
																															  SYS_vfork
#endif
};
// Set of System call numbers that terminates the tracee execution
const set<int> ProcessSyscallEntry::exitSyscalls = { SYS_exit, SYS_exit_group };
// Set of System call numbers that do not return, hence do not generate a notification at their exit
const set<int> ProcessSyscallEntry::nonReturningSyscalls = { SYS_rt_sigreturn };
// Returned when this ProcessState will NOT generate any child thread
const int ProcessSyscallEntry::NO_CHILD = -1;
// Returned when if this ProcessState succeed a child thread will be generated
const int ProcessSyscallEntry::POSSIBLE_CHILD = -2;

/**
 * Constructs a new ProcessSyscall, it only sets the timestamp variable.
 */
ProcessSyscallEntry::ProcessSyscallEntry(string notificationOrigin, int pid, int spid) : ProcessNotification(notificationOrigin, pid, spid) {
	this->setTimestamp();
}

/**
 * Prints to STDOUT all the available information about this ProcessState in a standard format.
 */
void ProcessSyscallEntry::print() const {
	cout << "------------------ SYSCALL ENTRY START ------------------" << endl;
  ProcessNotification::print();
  cout << "Syscall = " << SyscallNameResolver::resolve(this->getSyscall()) << " (" << this->getSyscall() << ")" << endl;
  cout << "Return value = " << this->returnValue << endl;
  if (!this->stackFrames.empty()) {
    cout << "Stack unwinding =" << endl;
    for (const StackFrame& i : this->stackFrames) {
      cout << string(i) << endl;
    }
  }
	cout << "Parameters = { ";
	for (unsigned long long int i = 0; i < Registers::ARGS_COUNT; i++) {
		cout << boost::format("%#016x\t") % this->argument(i);
	}
	cout << "}" << endl;
  if (this->regs != nullptr) {
    cout << string(*this->regs) << endl;
  }
  if (this->getChildPid() > 0) {
    cout << "Child PID = " << this->getChildPid() << endl;
    cout << "Child SPID = " << this->returnValue << endl;
    assert(this->returnValue > 0 && this->returnValue < Tracer::MAX_PID);
  }
	cout << "------------------ SYSCALL ENTRY STOP ------------------" << endl;
}

/**
 * Gets the Program Counter (aka Instruction Pointer) of this ProcessState.
 * 
 * @return The Program Counter.
 */
unsigned long long int ProcessSyscallEntry::getPc() const {
  return this->regs->pc();
}

/**
 * Gets the Stack Pointer of this ProcessState.
 *
 * @return The Stack Pointer.
 */
unsigned long long int ProcessSyscallEntry::getSp() const {
	return this->regs->sp();
}

/**
 * Gets the System Call number of this ProcessState.
 * 
 * @return The syscall number.
 */
int ProcessSyscallEntry::getSyscall() const {
  return this->regs->syscall();
}

/**
 * Gets the return value of this System Call.
 * Take into consideration that until a sysexit is not performed the syscall return value
 * will always be -ENOSYS.
 * There is a special case where even after a syscall exit the return value is still -ENOSYS
 * that is the rare event of a call of a not existent system call number.
 * 
 * @return The return value of a this system call.
 */
long long int ProcessSyscallEntry:: getReturnValue() const {
  return this->returnValue;
}

/**
 * If this system call has generated a child thus it is one of childSyscalls
 * if the return_value is positive a child thread has been created.
 * The child SPID can be found in the ProcessState return value and the child PID can be
 * retrieved through this method.
 * 
 * @return Returns: The child PID if it has been generated.
 *                  Tracer::NO_CHILD If this syscall has not generated any child.
 *                  Tracer::POSSIBLE_CHILD If this syscall is not yet authorised and if succeed
 *                                         it will generate a child.
 */
pid_t ProcessSyscallEntry::getChildPid() const {
  if (ProcessSyscallEntry::childGeneratingSyscalls.find(this->getSyscall()) != ProcessSyscallEntry::childGeneratingSyscalls.end()) {
    if (this->isAuthorised() && this->returnValue > 0 && this->returnValue < Tracer::MAX_PID) {
      assert(this->childPid > 0 && this->childPid < Tracer::MAX_PID);
      return this->childPid;
    }
    return ProcessSyscallEntry::POSSIBLE_CHILD;
  } else {
    assert(this->childPid < 0);
    return ProcessSyscallEntry::NO_CHILD;
  }
}

/**
 * Gets a pointer to the Tracer that has created this syscall notification.
 * 
 * @return The Tracer that has originated this object.
 */
shared_ptr<Tracer> ProcessSyscallEntry::getTracer() const {
  return this->tracer;
}

/**
 * This sets the syscall number, the list of call parameters and the ProcessState::regs_state pointer.
 * This is the first method to call after the ProcessState creation before the backtrace acquisition.
 * 
 * @param regs The Register object already acquired from the tracee.
 */
void ProcessSyscallEntry::setRegisters(shared_ptr<Registers> regs) {
  assert(this->regs == nullptr);
  assert(this->returnValue == -ENOSYS);
  assert(!this->isAuthorised());
  assert(this->stackFrames.empty());
  this->regs = regs;
}

/**
 * Gets the i-th argument for this system call.
 *
 * @param i The argument number that will be returned.
 * @return The i-th syscall argument.
 */
unsigned long long int ProcessSyscallEntry::argument(unsigned short int i) const {
	return this->regs->argument(i);
}

const std::vector<StackFrame>& ProcessSyscallEntry::getStackFrames() const {
	return this->stackFrames;
}
