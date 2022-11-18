#include <iostream>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <chrono>
#include "ProcessNotification.h"
#include "Launcher.h"
#include "ProcessSyscallEntry.h"

using namespace std;

/**
 * Build a new basic ProcessNotification given some essential information.
 * 
 * @param notification_origin The executable name that has generated this notification.
 * @param pid                 The Process ID of the thread that has generated this notification.
 * @param spid                The Thread ID of the thread that has generated this notification.
 */
ProcessNotification::ProcessNotification(string notification_origin, int pid, int spid) {
	this->setTimestamp();
  this->notificationOrigin = notification_origin;
  this->pid = pid;
  this->spid = spid;
}

/**
 * Gets the program name of the executable that generated this notification.
 * 
 * @return The executable name.
 */
string ProcessNotification::getExecutableName() const {
  return this->notificationOrigin;
}

/**
 * Sets the program executable name which originated this notification.
 * This is not serialised, the Mapper knows how to create different section for each executable name.
 * 
 * @param syscall_origin The program executable name.
 */
void ProcessNotification::setExecutableName(const string& syscall_origin) {
  assert(!syscall_origin.empty());
  this->notificationOrigin = syscall_origin;
}

/**
 * Gets the PID (aka process identifier) of the tracee that has generated this notification.
 * 
 * @return The PID that has generated this notification.
 */
pid_t ProcessNotification::getPid() const {
  return this->pid;
}

/**
 * Gets the SPID (aka TID or LWP) identifier of the tracee that has generated this notification.
 * 
 * @return The SPID that has generated this notification.
 */
pid_t ProcessNotification::getSpid() const {
  return this->spid;
}

/**
 * Prints to STDOUT all the available information about this ProcessNotification in a standard format.
 */
void ProcessNotification::print() const {
  if (!this->notificationOrigin.empty()) {
    cout << "Notification origin: " << this->notificationOrigin << endl;
  }
  cout << "PID: " << this->pid << endl;
  cout << "SPID: " << this->spid << endl;
	cout << "Timestamp: " << this->timestamp << endl;
  cout << (this->authorised ? "Authorized" : "NOT Authorized") << endl;
}

/**
 * Gets if this notification has already been authorised or not.
 * 
 * @return True if this notification has already been authorised, False otherwise.
 */
bool ProcessNotification::isAuthorised() const {
  return this->authorised;
}

/**
 * Gets the notification creation time.
 * 
 * @return A string containing the timestamp according with this locale.
 */
unsigned long long ProcessNotification::getTimestamp() const {
  assert(this->timestamp > 0);
  return this->timestamp;
}

/**
 * Authorise the tracer to proceed until the next notification.
 * 
 * @return False if this notification has already been authorised, True otherwise.
 */
bool ProcessNotification::authorise() {
  if(this->authorised) {
    return false;
  }
  return this->authorised = true;
}

/**
 * Sets a new notification origin executable name.
 * 
 * @param notification_origin The new notification origin executable name, not empty.
 */
void ProcessNotification::setNotificationOrigin(string notification_origin) {
  assert(!notification_origin.empty());
  this->notificationOrigin = notification_origin;
}

/**
 * Sets a new notification origin PID.
 * 
 * @param pid The new notification origin PID.
 */
void ProcessNotification::setPid(pid_t pid) {
  assert(pid > 0 && pid < Tracer::MAX_PID);
  this->pid = pid;
}

/**
 * Sets a new notification origin SPID.
 * 
 * @param spid The new notification origin SPID.
 */
void ProcessNotification::setSpid(pid_t spid) {
  assert(spid > 0 && spid < Tracer::MAX_PID);
  this->spid = spid;
}

/**
 * Sets the notification creation time in microseconds from epoch.
 */
void ProcessNotification::setTimestamp() {
	this->timestamp = chrono::time_point_cast<chrono::microseconds>(chrono::system_clock::now()).time_since_epoch().count();
  //this->_timestamp = std::chrono::duration_cast<std::chrono::microseconds> (std::chrono::high_resolution_clock::now().time_since_epoch()).count();
}