/* 
 * File:   ProcessTermination.cpp
 * Author: Matteo De Giorgi
 * 
 * Created on 14 January 2017, 16:43
 */

#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <iostream>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdexcept>
#include <string.h>
#include <vector>
#include "Launcher.h"
#include "ProcessTermination.h"
#include "Tracer.h"

using namespace std;

/**
 * Build a new process death notification.
 * The passed waitpid status must be a termination status.
 * 
 * @param notificationOrigin The executable name (with or without path) that has generated this notification
 * @param pid                The Process ID of the thread that has generated this notification.
 * @param spid               The Thread ID of the thread that has generated this notification.
 * @param returnValue        The thread exit status.
 * @param waitpidStatus      The status obtained via a waitpid system call that has generated this notification.
 */
ProcessTermination::ProcessTermination(string notificationOrigin,
                                       int pid,
                                       int spid,
                                       int returnValue,
                                       int waitpidStatus) : ProcessNotification(notificationOrigin, pid, spid),
                                                            waitpidStatus (waitpidStatus),
                                                            returnValue (returnValue) {
}

/**
 * Gets the thread exit status.
 * 
 * @return The thread exit status.
 */
int ProcessTermination::getExitStatus() const {
  return this->waitpidStatus > 0 ? WEXITSTATUS(this->waitpidStatus) : returnValue;
}

/**
 * Gets if the thread has been terminated thanks to a signal or not.
 * 
 * @return True if the thread has been terminated by a signal, False otherwise.
 */
bool ProcessTermination::isSignaled() const {
  return this->waitpidStatus > 0 ? WIFSIGNALED(this->waitpidStatus) : false;
}

/**
 * Gets the thread termination signal.
 * 
 * @return The signal number that has terminated this thread or a negative number
 *         if it was not terminated by a signal or we have not enough information to 
 *         determine it.
 */
int ProcessTermination::getTerminationSignal() const {
  if (this->waitpidStatus > 0) {
    return this->isSignaled() ? WTERMSIG(this->waitpidStatus) : -1;
  }
  return -1;
}

/**
 * Gets if the thread exit due to a signal has generated a core dump.
 * 
 * @return True if a core dump has been generated, False otherwise.
 */
bool ProcessTermination::isCoredumpGenerated() const {
  if (this->waitpidStatus > 0) {
    return this->isSignaled() ? WCOREDUMP(this->waitpidStatus) : false;
  }
  return false;
}

/**
 * Prints to STDOUT all the available information about this ProcessTermination in a standard format.
 */
void ProcessTermination::print() const {
	cout << "------------------ PROCESS TERMINATION START ------------------" << endl;
	ProcessNotification::print();
  if (this->waitpidStatus > 0) {
    cout << "Exit status: " << this->getExitStatus() << endl;
    if (this->isSignaled()) {
      cout << "Termination signal: " << this->getTerminationSignal() << endl;
      cout << "Signal description: " << string(strsignal(this->getTerminationSignal())) << endl;
      cout << "Core dump " << (this->isCoredumpGenerated() ? "" : "NOT") << " generated: " << endl;
    }
  } else {
    cout << "Exit status: " << this->returnValue << endl;
  }
	cout << "------------------ PROCESS TERMINATION STOP ------------------" << endl;
}