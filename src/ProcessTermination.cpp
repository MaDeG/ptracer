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
 * @param notification_origin The executable name (with or without path) that has generated this notification
 * @param pid                 The Process ID of the thread that has generated this notification.
 * @param spid                The Thread ID of the thread that has generated this notification.
 * @param waitpid_status      The status obtained via a waitpid system call that has generated this notification.
 * @param return_value        The thread exit status.
 * @throws runtime_error if WIFEXITED(this->_waitpid_status) is not true.
 */
ProcessTermination::ProcessTermination(string notification_origin,
                                       int pid,
                                       int spid,
                                       int waitpid_status,
                                       int return_value) : ProcessNotification(notification_origin, pid, spid),
                                                           _waitpid_status (waitpid_status),
                                                           _return_value   (return_value)                       {
}

/**
 * Constructs a new ProcessTermination given its serialised representation.
 * 
 * @param flat The ProcessTermination flat representation.
 * @thrown runtime_error If the given string is malformed.
 */
ProcessTermination::ProcessTermination(string flat) {
  vector<string> tokens;
  int status;
  this->set_timestamp();
  boost::split(tokens, flat, boost::is_any_of(ProcessNotification::FIELD_SEPARATOR));
  if (tokens.size() != 5) {
    throw new runtime_error("Impossible to deserialise a malformed ProcessTermination: " + flat);
  }
  for (string i : tokens) {
    if (i.empty()) {
      throw new runtime_error("Impossible to deserialise a malformed ProcessTermination due to a blank field: " + flat);
    }
  }
  this->set_executable_name(tokens.at(1));
  this->set_pid(boost::lexical_cast<pid_t>(tokens.at(2)));
  if (this->get_pid() <= 0 || this->get_pid() >= Tracer::MAX_PID) {
    throw new runtime_error("Found an invalid ProcessTermination PID field: " + tokens.at(2));
  }
  this->set_spid(boost::lexical_cast<pid_t>(tokens.at(3)));
  if (this->get_spid() <= 0 || this->get_spid() >= Tracer::MAX_PID) {
    throw new runtime_error("Found an invalid ProcessTermination SPID field: " + tokens.at(3));
  }
  status = boost::lexical_cast<int>(tokens.at(4));
  this->_waitpid_status = -1;
  this->_return_value = status;
}


/**
 * Copy constructor that pilfers all the ProcessTermination and ProcessNotification variables.
 * 
 * @param orig The ProcessTermintion that will be copied.
 */
ProcessTermination::ProcessTermination(const ProcessTermination& orig) : ProcessNotification(orig),
                                                                         _waitpid_status (orig._waitpid_status),
                                                                         _return_value   (orig._return_value)    {
  if (!WIFEXITED(this->_waitpid_status)) {
    throw new runtime_error("Copied a non termination status to a ProcessTermination notification type");
  }
}

/**
 * Gets the thread exit status.
 * 
 * @return The thread exit status.
 */
int ProcessTermination::get_exit_status() const {
  return this->_waitpid_status > 0 ? WEXITSTATUS(this->_waitpid_status) : _return_value;
}

/**
 * Gets if the thread has been terminated thanks to a signal or not.
 * 
 * @return True if the thread has been terminated by a signal, False otherwise.
 */
bool ProcessTermination::is_signaled() const {
  return this->_waitpid_status > 0 ? WIFSIGNALED(this->_waitpid_status) : false;
}

/**
 * Gets the thread termination signal.
 * 
 * @return The signal number that has terminated this thread or a negative number
 *         if it was not terminated by a signal or we have not enough information to 
 *         determine it.
 */
int ProcessTermination::get_termination_signal() const {
  if (this->_waitpid_status > 0) {
    return this->is_signaled() ? WTERMSIG(this->_waitpid_status) : -1;
  }
  return -1;
}

/**
 * Gets if the thread exit due to a signal has generated a core dump.
 * 
 * @return True if a core dump has been generated, False otherwise.
 */
bool ProcessTermination::is_coredump_generated() const {
  if (this->_waitpid_status > 0) {
    return this->is_signaled() ? WCOREDUMP(this->_waitpid_status) : false;
  }
  return false;
}

/**
 * Prints to STDOUT all the available information about this ProcessTermination in a standard format.
 */
void ProcessTermination::print() const {
  cout << "Executable name that is terminated: " << this->get_executable_name() << endl;
  cout << "Terminated PID: " << this->get_pid() << endl;
  cout << "Terminated SPID: " << this->get_spid() << endl;
  if (this->_waitpid_status > 0) {
    cout << "Exit status: " << this->get_exit_status() << endl;
    if (this->is_signaled()) {
      cout << "Termination signal: " << this->get_termination_signal() << endl;
      cout << "Signal description: " << string(strsignal(this->get_termination_signal())) << endl;
      cout << "Core dump generated: " << (this->is_coredump_generated() ? "true" : "false") << endl;
    }
  } else {
    cout << "Exit status: " << this->_return_value << endl;
  }
}

/**
 * Gives the serialised format of this ProcessTermiantion.
 * 
 * @return A string representation of this ProcessTermination.
 */
string ProcessTermination::serialize() const {
  string flat;
  flat = "ProcessTermination" + ProcessNotification::FIELD_SEPARATOR;
  flat += this->get_executable_name() + ProcessNotification::FIELD_SEPARATOR;
  flat += to_string(this->get_pid()) + ProcessNotification::FIELD_SEPARATOR;
  flat += to_string(this->get_spid()) + ProcessNotification::FIELD_SEPARATOR;
  flat += to_string(this->get_exit_status()) + "\n";
  return flat;
}