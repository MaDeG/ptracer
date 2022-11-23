#include <boost/format.hpp>
#include <iostream>
#include <utility>
#include "ProcessSyscallExit.h"

using namespace std;

/**
 * Constructs a new Syscall Exit, triggered when the kernel completes a syscall.
 *
 * @param notificationOrigin The program name that has requested the syscall.
 * @param pid The PID of the process that has invoked the syscall.
 * @param spid The Thread ID of the thread that has invoked the syscall.
 * @param returnValue The return value that will be reported to the tracee.
 */
ProcessSyscallExit::ProcessSyscallExit(string notificationOrigin, pid_t pid, pid_t spid, shared_ptr<Registers> regs) : ProcessNotification(notificationOrigin, pid, spid),
                                                                                                                       regs(std::move(regs)) {
	// Exit notifications are always authorised since the action has already happened
	this->authorise();
}

/**
 * Gets the actual syscall return value that will be reported to the tracee.
 *
 * @return The syscall return value.
 */
unsigned long long int ProcessSyscallExit::getReturnValue() const {
	return this->regs->returnValue();
}

/**
 * Gets the syscall number that has just returned.
 *
 * @return The syscall number.
 */
int ProcessSyscallExit::getSyscall() const {
	return this->regs->syscall();
}

/**
 * Pretty print for this syscall exit.
 */
void ProcessSyscallExit::print() const {
	cout << "------------------ SYSCALL EXIT START ------------------" << endl;
	ProcessNotification::print();
	cout << (boost::format("Return value: %#016x") % this->getReturnValue()).str() << endl;
	cout << "------------------ SYSCALL EXIT STOP ------------------" << endl;
}