#include <iostream>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include "ProcessNotification.h"
#include "Launcher.h"
#include "ProcessSyscall.h"

using namespace std;

// Used as separator among the flat version fields
const string ProcessNotification::FIELD_SEPARATOR = " ";
// Used to mark a serialised ProcessNotification as authorised
const string ProcessNotification::AUTHORISED_SPEC = "Authorised";
// Used to mark a serialised ProcessNotification as NOT authorised
const string ProcessNotification::NOT_AUTHORISED_SPEC = "Not Authorised";

/**
 * Build a new basic ProcessNotification given some essential information.
 * 
 * @param notification_origin The executable name that has generated this notification.
 * @param pid                 The Process ID of the thread that has generated this notification.
 * @param spid                The Thread ID of the thread that has generated this notification.
 */
ProcessNotification::ProcessNotification(string notification_origin, int pid, int spid) {
  this->set_timestamp();
  this->_notification_origin = notification_origin;
  this->_pid = pid;
  this->_spid = spid;
}

ProcessNotification::ProcessNotification(string flat) {
  vector<string> tokens;
  boost::split(tokens, flat, boost::is_any_of(ProcessNotification::FIELD_SEPARATOR));
  this->set_timestamp();
  if (tokens.size() != 5) {
    throw new runtime_error("Impossible to deserialise a malformed ProcessNotification: " + flat);
  }
  for (string i : tokens) {
    if (i.empty()) {
      throw new runtime_error("Impossible to deserialise a malformed ProcessNotification due to a blank field: " + flat);
    }
  }
  this->_notification_origin = tokens.at(1);
  this->_pid = boost::lexical_cast<pid_t>(tokens.at(2));
  if (this->_pid <= 0 || this->_pid >= Tracer::MAX_PID) {
    throw new runtime_error("Found an invalid ProcessNotification PID field: " + tokens.at(2));
  }
  this->_spid = boost::lexical_cast<pid_t>(tokens.at(3));
  if (this->_spid <= 0 || this->_spid >= Tracer::MAX_PID) {
    throw new runtime_error("Found an invalid ProcessNotification SPID field: " + tokens.at(3));
  }
  if (tokens.at(4) == ProcessNotification::AUTHORISED_SPEC) {
    this->_authorised = true;
  } else if (tokens.at(4) == ProcessNotification::NOT_AUTHORISED_SPEC) {
    this->_authorised = false;
  } else {
    throw new runtime_error("Found an invalid ProcessNotification authorised field: " + tokens.at(4));
  }
}

/**
 * Copy constructor that pilfers all the ProcessNotification variables.
 * 
 * @param orig The ProcessNotification that will be copied.
 */
ProcessNotification::ProcessNotification(const ProcessNotification& orig) : _notification_origin (move(orig._notification_origin)),
                                                                            _pid                 (orig._pid),
                                                                            _spid                (orig._spid),
                                                                            _authorised          (orig._authorised)                 {
  assert(!this->_notification_origin.empty());
}

/**
 * Gets the program name of the executable that generated this notification.
 * 
 * @return The executable name.
 */
string ProcessNotification::get_executable_name() const {
  return this->_notification_origin;
}

/**
 * Sets the program executable name which originated this notification.
 * This is not serialised, the Mapper knows how to create different section for each executable name.
 * 
 * @param notification_origin The program executable name.
 */
void ProcessNotification::set_executable_name(const string& notification_origin) {
  assert(!notification_origin.empty());
  this->_notification_origin = notification_origin;
}

/**
 * Gets the PID (aka process identifier) of the tracee that has generated this notification.
 * 
 * @return The PID that has generated this notification.
 */
pid_t ProcessNotification::get_pid() const {
  return this->_pid;
}

/**
 * Gets the SPID (aka TID or LWP) identifier of the tracee that has generated this notification.
 * 
 * @return The SPID that has generated this notification.
 */
pid_t ProcessNotification::get_spid() const {
  return this->_spid;
}

/**
 * Prints to STDOUT all the available information about this ProcessNotification in a standard format.
 */
void ProcessNotification::print() const {
  if (!this->_notification_origin.empty()) {
    cout << "Notification origin: " << this->_notification_origin << endl;
  }
  cout << "Notification origin PID: " << this->_pid << endl;
  cout << "Notification origin SPID: " << this->_spid << endl;
  cout << "Authorised notification: " << (this->_authorised ? "true" : "false") << endl;
}

/**
 * Define the serialised format of a ProcessNotification.
 * 
 * @return This ProcessNotification in a flat format.
 */
string ProcessNotification::serialize() const {
  string flat;
  flat = "ProcessNotification" + ProcessNotification::FIELD_SEPARATOR;
  flat += this->_notification_origin + ProcessNotification::FIELD_SEPARATOR;
  flat += to_string(this->_pid) + ProcessNotification::FIELD_SEPARATOR;
  flat += to_string(this->_spid) + ProcessNotification::FIELD_SEPARATOR;
  flat += (this->_authorised ? ProcessNotification::AUTHORISED_SPEC : ProcessNotification::NOT_AUTHORISED_SPEC);
  flat += "\n";
  return flat;
}

/**
 * Defines the XES representation of a ProcessNotification.
 * This does not set the element concept:name.
 * 
 * @return An element of "event" type of the XES format.
 */
boost::property_tree::ptree ProcessNotification::get_xes() const {
  boost::property_tree::ptree event_node;
  boost::property_tree::ptree timestamp;
  boost::property_tree::ptree transition;
  boost::property_tree::ptree resource;
  // Key attributes set
  timestamp.put("<xmlattr>.key", "time:timestamp");
  transition.put("<xmlattr>.key", "lifecycle:transition");
  resource.put("<xmlattr>.key", "org:resource");
  // Value attributes set
  timestamp.put("<xmlattr>.value", this->_timestamp);
  transition.put("<xmlattr>.value", "complete");
  resource.put("<xmlattr>.value", this->get_executable_name());
  // Add to root element
  event_node.add_child("date", timestamp);
  event_node.add_child("string", transition);
  event_node.add_child("string", resource);
  return event_node;
}

/**
 * Gets if this notification has already been authorised or not.
 * 
 * @return True if this notification has already been authorised, False otherwise.
 */
bool ProcessNotification::is_authorised() const {
  return this->_authorised;
}

/**
 * Gets the notification creation time.
 * 
 * @return A string containing the timestamp according with this locale.
 */
string ProcessNotification::get_timestamp() const {
  assert(!this->_timestamp.empty());
  return this->_timestamp;
}

/**
 * Authorise the tracer to proceed until the next notification.
 * 
 * @return False if this notification has already been authorised or an error occurred, True otherwise.
 */
bool ProcessNotification::authorise() {
  if(this->_authorised) {
    return false;
  }
  this->_authorised = true;
  return true;
}

/**
 * Sets a new notification origin executable name.
 * 
 * @param notification_origin The new notification origin executable name, not empty.
 */
void ProcessNotification::set_notification_origin(string notification_origin) {
  assert(!notification_origin.empty());
  this->_notification_origin = notification_origin;
}

/**
 * Sets a new notification origin PID.
 * 
 * @param pid The new notification origin PID.
 */
void ProcessNotification::set_pid(pid_t pid) {
  assert(pid > 0 && pid < Tracer::MAX_PID);
  this->_pid = pid;
}

/**
 * Sets a new notification origin SPID.
 * 
 * @param spid The new notification origin SPID.
 */
void ProcessNotification::set_spid(pid_t spid) {
  assert(spid > 0 && spid < Tracer::MAX_PID);
  this->_spid = spid;
}

/**
 * A ProcessNotification can, other then itself, be a ProcessSyscall or a ProcessTermination,
 * this method ensures that the proper deserialisation procedure is called.
 * 
 * @param flat         The string which contains the serialised ProcessNotification.
 * @param no_backtrace If this ProcessNotification is a ProcessSyscall this is a required parameter.
 * @return The deserialised ProcessNotification object.
 */
shared_ptr<ProcessNotification> ProcessNotification::deserialize(string flat, bool no_backtrace) {
  assert(!flat.empty());
  shared_ptr<ProcessNotification> notification = nullptr;
  try {
    if (boost::starts_with(flat, "ProcessNotification")) {
      notification = make_shared<ProcessNotification>(flat);
    } else if (boost::starts_with(flat, "ProcessTermination")) {
      notification = make_shared<ProcessTermination>(flat);
    } else {
      notification = make_shared<ProcessSyscall>(flat, no_backtrace);
    }
  } catch (runtime_error& e) {
    // Nothing, notification will stay nullptr
  }
  return notification;
}

/**
 * Sets the notification creation time according to the current locale.
 */
void ProcessNotification::set_timestamp() {
  assert(this->_timestamp.empty());
  boost::posix_time::time_facet* facet = new boost::posix_time::time_facet("%Y-%m-%dT%H:%M:%S.%f%Q");
  stringstream date_stream;
  date_stream.imbue(locale(date_stream.getloc(), facet));
  date_stream << boost::posix_time::microsec_clock::universal_time();
  this->_timestamp = date_stream.str();
  this->_timestamp.erase(this->_timestamp.size() - 3, this->_timestamp.size());
  this->_timestamp += "+01:00";
}