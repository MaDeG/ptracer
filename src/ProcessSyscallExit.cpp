#include <boost/format.hpp>
#include <iostream>
#include "ProcessSyscallExit.h"

using namespace std;

ProcessSyscallExit::ProcessSyscallExit(string notificationOrigin, pid_t pid, pid_t spid, unsigned long long int returnValue) : ProcessNotification(notificationOrigin, pid, spid),
                                                                                                                               returnValue(returnValue) {
	// Exit notifications are always authorised since the action has already happened
	this->authorise();
}

unsigned long long int ProcessSyscallExit::getReturnValue() const {
	return this->returnValue;
}

void ProcessSyscallExit::print() const {
	cout << "------------------ SYSCALL EXIT START ------------------" << endl;
	ProcessNotification::print();
	cout << (boost::format("Return value: %#016x") % this->getReturnValue()).str() << endl;
	cout << "------------------ SYSCALL EXIT STOP ------------------" << endl;
}