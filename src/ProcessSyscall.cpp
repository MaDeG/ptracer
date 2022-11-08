#include <string>
#include <vector>
#include <iostream>
#include <string.h>
#include <sys/syscall.h>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/format.hpp>
#include "Tracer.h"
#include "ProcessSyscall.h"
#include "TracingManager.h"
#include "Launcher.h"

using namespace std;

// Set of System calls numbers that may generate a child
const set<int> ProcessSyscall::childGeneratingSyscalls = {SYS_clone,
#ifdef ARCH_X86_64
																									SYS_fork,
																									SYS_vfork
#endif
};
// Set of System calls number that terminates the tracee execution
const set<int> ProcessSyscall::exitSyscalls = {SYS_exit, SYS_exit_group };
// Returned when this ProcessState will NOT generate any child thread
const int ProcessSyscall::NO_CHILD = -1;
// Returned when if this ProcessState succeed a child thread will be generated
const int ProcessSyscall::POSSIBLE_CHILD = -2;

/**
 * Copy constructor that pilfers all the ProcessState variables.
 * 
 * @param ps The ProcessState that will be copied.
 */
ProcessSyscall::ProcessSyscall(const ProcessSyscall& ps) : ProcessNotification(ps),
                                                           returnValue (move(ps.returnValue)),
                                                           regs        (move(ps.regs)),
                                                           stackFrames (move(ps.stackFrames)),
                                                           childPid    (move(ps.childPid))     {
  assert(this->getChildPid());
}

/**
 * Constructs a new ProcessSyscall, it only sets the timestamp variable.
 */
ProcessSyscall::ProcessSyscall() {
	this->setTimestamp();
}

/**
 * Prints to STDOUT all the available information about this ProcessState in a standard format.
 */
void ProcessSyscall::print() const {
  cout << "Executable name = " << this->getExecutableName() << endl;
  if (this->getPid() > 0 && this->getPid() < Tracer::MAX_PID) {
    cout << "Process PID = " << this->getPid() << endl;
  }
  if (this->getSpid() > 0 && this->getSpid() < Tracer::MAX_PID) {
    cout << "Process SPID = " << this->getSpid() << endl;
  }
  cout << "Syscall number = " << this->getSyscall() << endl;
  cout << "Return value = " << this->returnValue << endl;
  if (!this->stackFrames.empty()) {
    cout << "Stack unwinding =" << endl;
    for (const StackFrame& i : this->stackFrames) {
      cout << string(i) << endl;
    }
  }
	cout << "Parameters = {  ";
	for (unsigned long long int i = 0; i < Registers::ARGS_COUNT; i++) {
		cout << boost::format("%#016x\t") % this->argument(i);
	}
	cout << "}" << endl;
  if (this->regs != nullptr) {
    cout << "Registers = {  ";
    cout << boost::format("PC : %#016x\t") % this->getPc();
    cout << boost::format("SP : %#016x\t") % this->getSp();
    cout << boost::format("RET : %#016x\t") % this->getReturnValue();
    cout << "}" << endl;
  }
  if (this->getChildPid() > 0) {
    cout << "Child PID = " << this->getChildPid() << endl;
    cout << "Child SPID = " << this->returnValue << endl;
    assert(this->returnValue > 0 && this->returnValue < Tracer::MAX_PID);
  }
  cout << "Timestamp = " << this->getTimestamp() << endl;
}

/**
 * Gets the Program Counter (aka Instruction Pointer) of this ProcessState.
 * 
 * @return The Program Counter.
 */
unsigned long long int ProcessSyscall::getPc() const {
  return this->regs->pc();
}

/**
 * Gets the Stack Pointer of this ProcessState.
 *
 * @return The Stack Pointer.
 */
unsigned long long int ProcessSyscall::getSp() const {
	return this->regs->sp();
}

/**
 * Gets the System Call number of this ProcessState.
 * 
 * @return The syscall number.
 */
int ProcessSyscall::getSyscall() const {
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
long long int ProcessSyscall:: getReturnValue() const {
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
pid_t ProcessSyscall::getChildPid() const {
  if (ProcessSyscall::childGeneratingSyscalls.find(this->getSyscall()) != ProcessSyscall::childGeneratingSyscalls.end()) {
    if (this->isAuthorised() && this->returnValue > 0 && this->returnValue < Tracer::MAX_PID) {
      assert(this->childPid > 0 && this->childPid < Tracer::MAX_PID);
      return this->childPid;
    }
    return ProcessSyscall::POSSIBLE_CHILD;
  } else {
    assert(this->childPid < 0);
    return ProcessSyscall::NO_CHILD;
  }
}

/**
 * Gets a pointer to the Tracer that has created this syscall notification.
 * 
 * @return The Tracer that has originated this object.
 */
shared_ptr<Tracer> ProcessSyscall::getTracer() const {
  return this->tracer;
}

/**
 * This sets the syscall number, the list of call parameters and the ProcessState::regs_state pointer.
 * This is the first method to call after the ProcessState creation before the backtrace acquisition.
 * 
 * @param regs The Register object already acquired from the tracee.
 */
void ProcessSyscall::setRegisters(shared_ptr<Registers> regs) {
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
unsigned long long int ProcessSyscall::argument(unsigned short int i) const {
	return this->regs->argument(i);
}