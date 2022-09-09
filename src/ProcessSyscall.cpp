#include <string>
#include <vector>
#include <iostream>
#include <string.h>
#include <sys/syscall.h>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include "Tracer.h"
#include "ProcessSyscall.h"
#include "TracingManager.h"
#include "Launcher.h"

using namespace std;

// Delimiter that will be used to separate fields in the serialized representation
const string ProcessSyscall::FIELD_SEPARATOR = ";";
// Separator that will be used to separate values inside a filed in the serialized representation
const string ProcessSyscall::VALUE_SEPARATOR = ",";
// Line delimiter that will be used to indicate the end of a serialized object
const string ProcessSyscall::END_OF_OBJECT = "\n";
// Set of System calls numbers that may generate a child
const set<int> ProcessSyscall::child_syscalls = { SYS_clone,
#ifdef ARCH_X86_64
																									SYS_fork,
																									SYS_vfork
#endif
};
// Set of System calls number that terminates the tracee execution
const set<int> ProcessSyscall::exit_syscalls = { SYS_exit, SYS_exit_group };
// Returned when this ProcessState will NOT generate any child thread
const int ProcessSyscall::NO_CHILD = -1;
// Returned when if this ProcessState succeed a child thread will be generated
const int ProcessSyscall::POSSIBLE_CHILD = -2;

/**
 * Given a serialised representation of a ProcessState object this is able to deserialise it.
 * Only Sytem call number and Backtrack function names with relative offset will be restored.
 * 
 * @param flat The string representation of a serialised ProcessState.
 */
ProcessSyscall::ProcessSyscall(string flat, bool no_backtrace) {
  string nsyscall, backtrace_data;
  vector<string> tokens;
  this->set_timestamp();
  boost::split(tokens, flat, boost::is_any_of(ProcessSyscall::FIELD_SEPARATOR));
  if ((tokens.size() == 5 && !no_backtrace) || (tokens.size() == 6 && no_backtrace)) {
    // Not minimal flat format deserialisation
    this->set_executable_name(tokens.at(0));
    this->set_pid(boost::lexical_cast<pid_t>(tokens.at(1)));
    if (this->get_pid() < 0 || this->get_pid() > Tracer::MAX_PID) {
      throw new runtime_error("Error in ProcessSyscall deserialisation: not valid PID value");
    }
    this->set_spid(boost::lexical_cast<pid_t>(tokens.at(2)));
    if (this->get_spid() < 0 || this->get_spid() > Tracer::MAX_PID) {
      throw new runtime_error("Error in ProcessSyscall deserialisation: not valid SPID value");
    }
    tokens.erase(tokens.begin(), tokens.begin() + 3);
    if ((tokens.size() == 3 && !no_backtrace) || (tokens.size() == 4 && no_backtrace)) {
      this->child_pid = boost::lexical_cast<pid_t>(tokens.at(0));
      assert(this->child_pid > 0 && this->child_pid < Tracer::MAX_PID);
      assert(this->return_value > 0 && this->return_value < Tracer::MAX_PID);
      tokens.erase(tokens.begin());
    }
  }
  if ((tokens.size() != 2 && !no_backtrace) || (tokens.size() != 3 && no_backtrace)) {
    throw new runtime_error("Error in the ProcessSyscall deserialisation: format not correct");
  }
  this->nsyscall = boost::lexical_cast<int>(tokens.at(0));
  if (this->nsyscall < 0) {
    throw new runtime_error("Error in ProcessSyscall deserialisation: not valid syscall number: " + nsyscall);
  }
  if (no_backtrace) {                                                           // Expected only PC and SP
    this->pc_backtrace.push_back(stoll(tokens.at(1)));
    this->sp_backtrace.push_back(stoll(tokens.at(2)));
  } else {
    backtrace_data = tokens.at(1);
    tokens.clear();
    boost::split(tokens, backtrace_data, boost::is_any_of(ProcessSyscall::VALUE_SEPARATOR));
    for (string& entry : tokens) {
      this->fn_backtrace.emplace_back(entry);
    }
    // TODO: Add call params, registers, pc and sp backtrack deserialization, in the future...
  }
}

/**
 * Copy constructor that pilfers all the ProcessState variables.
 * 
 * @param ps The ProcessState that will be copied.
 */
ProcessSyscall::ProcessSyscall(const ProcessSyscall& ps) : ProcessNotification(ps),
                                                           nsyscall       (move(ps.nsyscall)),
                                                           return_value   (move(ps.return_value)),
                                                           relative_pc    (move(ps.relative_pc)),
                                                           regs_state     (move(ps.regs_state)),
                                                           fn_backtrace   (move(ps.fn_backtrace)),
                                                           pc_backtrace   (move(ps.pc_backtrace)),
                                                           sp_backtrace   (move(ps.sp_backtrace)),
                                                           call_param     (move(ps.call_param)),
                                                           child_pid      (move(ps.child_pid))     {
  assert(!this->fn_backtrace.empty() || (!this->pc_backtrace.empty() && !this->sp_backtrace.empty()));
  assert(this->get_child_pid());
}

/**
 * Constructs a new ProcessSyscall, it only sets the timestamp variable.
 */
ProcessSyscall::ProcessSyscall() {
  this->set_timestamp();
}

/**
 * Generates a serialised version of this ProcessState object with the most important
 * information that can identify a syscall: 
 * System call number, Backtrack function names with relative offset.
 * A constructor is able to do the inverse operation.
 * 
 * @return The serialised object in string format.
 */
string ProcessSyscall::serialize() const {
  string flat;
  flat += to_string(this->nsyscall) + ProcessSyscall::FIELD_SEPARATOR;
  if (this->fn_backtrace.empty()) {
    assert(this->pc_backtrace.size() == 1);
    assert(this->sp_backtrace.size() == 1);
    flat += to_string(this->pc_backtrace.at(0));
    flat += ProcessSyscall::FIELD_SEPARATOR;
    flat += to_string(this->sp_backtrace.at(0));
  } else {
    for (auto& i : this->fn_backtrace) {
      flat += string(i) + ProcessSyscall::VALUE_SEPARATOR;
    }
    flat.resize(flat.size() - ProcessSyscall::VALUE_SEPARATOR.size());
  }
  /*flat += ProcessSyscall::FIELD_DELIMITER;
  for (unsigned long long int i : this->pc_backtrace) {
    flat += to_string(i) + ProcessSyscall::VALUE_SEPARATOR;
  }
  flat.resize(flat.size() - ProcessSyscall::VALUE_SEPARATOR.size());
  flat += ProcessSyscall::FIELD_DELIMITER;
  for (unsigned long long int i : this->sp_backtrace) {
    flat += to_string(i) + ProcessSyscall::VALUE_SEPARATOR;
  }
  flat.resize(flat.size() - ProcessSyscall::VALUE_SEPARATOR.size());*/
  // TODO: Add registers, program counters and stack frames serialization
  flat += END_OF_OBJECT;
  return flat;
}

/**
 * Generates a serialised version of this ProcessState object with the most important
 * information that can identify a syscall: 
 * PID, SPID, System call number, Backtrack function names with relative offset.
 * A constructor is able to do the inverse operation.
 * 
 * @param is_minimal
 * @return 
 */
string ProcessSyscall::serialize_not_minimal() const {
  string flat;
  flat = this->get_executable_name() + ProcessSyscall::FIELD_SEPARATOR;
  flat += to_string(this->get_pid()) + ProcessSyscall::FIELD_SEPARATOR;
  flat += to_string(this->get_spid()) + ProcessSyscall::FIELD_SEPARATOR;
  if (this->child_pid > 0) {
    flat += to_string(this->child_pid) + ProcessSyscall::FIELD_SEPARATOR;
  }
  flat += this->serialize();
  return flat;
}

/**
 * Prints to STDOUT all the available information about this ProcessState in a standard format.
 */
void ProcessSyscall::print() const {
  cout << "Executable name = " << this->get_executable_name() << endl;
  if (this->get_pid() > 0 && this->get_pid() < Tracer::MAX_PID) {
    cout << "Process PID = " << this->get_pid() << endl;
  }
  if (this->get_spid() > 0 && this->get_spid() < Tracer::MAX_PID) {
    cout << "Process SPID = " << this->get_spid() << endl;
  }
  cout << "Syscall number = " << this->nsyscall << endl;
  cout << "Return value = " << this->return_value << endl;
  if (this->relative_pc > 0) {
    cout << "Relative_PC = " << this->relative_pc << endl;
  }
  if (!this->fn_backtrace.empty()) {
    cout << "Function names backtrack = {  ";
    for (auto& i : this->fn_backtrace) {
      cout << string(i) << "   ";
    }
    cout << "}" << endl;
  }
  if (!this->pc_backtrace.empty()) {
    cout << "Program counters backtrack = {  ";
    for (long long int i : this->pc_backtrace) {
      cout << to_string(i) << "   ";
    }
    cout << "}" << endl;
  }
  if (!this->sp_backtrace.empty()) {
    cout << "Stack backtrack = {  ";
    for (long long int i : this->sp_backtrace) {
      cout << to_string(i) << "   ";
    }
    cout << "}" << endl;
  }
  if (!this->call_param.empty()) {
    cout << "Parameters = {  ";
    for (unsigned long long int i : this->call_param) {
      cout << to_string(i) << "   ";
    }
    cout << "}" << endl;
  }
  if (this->regs_state != nullptr) {
    cout << "Registers = {  ";
    cout << "PC : " << this->regs_state->pc() << "  ";
    cout << "SP : " << this->regs_state->sp() << "  ";
    cout << "RET : " << this->regs_state->ret_arg() << "  ";
    cout << "}" << endl;
  }
  if (this->get_child_pid() > 0) {
    cout << "Child PID = " << this->get_child_pid() << endl;
    cout << "Child SPID = " << this->return_value << endl;
    assert(this->return_value > 0 && this->return_value < Tracer::MAX_PID);
  }
  cout << "Timestamp = " << this->get_timestamp() << endl;
}

/**
 * Gets the relative Program Counter (aka Instruction Pointer) of this ProcessState.
 * 
 * @return The relative Program Counter.
 */
long long int ProcessSyscall::get_pc() const {
  return this->relative_pc;
}

/**
 * Gets the System Call number of this ProcessState.
 * 
 * @return The syscall number.
 */
int ProcessSyscall::get_nsyscall() const {
  return this->nsyscall;
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
long long int ProcessSyscall::get_return_value() const {
  return this->return_value;
}

/**
 * If this system call has generated a child thus it is a SYS_fork or SYS_vfork or SYS_clone
 * if the return_value is positive a child thread has been created.
 * The child SPID can be found in the ProcessState return value and the child PID can be
 * retrieved through this method.
 * 
 * @return Returns: The child PID if it has been generated.
 *                  Tracer::NO_CHILD If this syscall has not generated any child.
 *                  Tracer::POSSIBLE_CHILD If this syscall is not yet authorised and if succeed
 *                                         it will generate a child.
 */
pid_t ProcessSyscall::get_child_pid() const {
  if (ProcessSyscall::child_syscalls.find(this->nsyscall) != ProcessSyscall::child_syscalls.end()) {
    if (this->is_authorised() && this->return_value > 0 && this->return_value < Tracer::MAX_PID) {
      assert(this->child_pid > 0 && this->child_pid < Tracer::MAX_PID);
      return this->child_pid;
    }
    return ProcessSyscall::POSSIBLE_CHILD;
  } else {
    assert(this->child_pid < 0);
    return ProcessSyscall::NO_CHILD;
  }
}

/**
 * Gets a pointer to the Tracer that has created this syscall notification.
 * 
 * @return The Tracer that has originated this object.
 */
shared_ptr<Tracer> ProcessSyscall::get_tracer() const {
  return this->tracer;
}

/**
 * Define the equality check that Bimap will use to find a ProcessState
 * 
 * @param compare The ProcessState that will be checked for equality.
 * @return True if this == compare, False otherwise.
 */
bool ProcessSyscall::operator==(const ProcessSyscall& compare) const {
  if (this->nsyscall != compare.nsyscall) {
    return false;
  }
  if (this->fn_backtrace.empty()) {
    assert(this->pc_backtrace.size() == 1 && this->sp_backtrace.size() == 1);
    assert(compare.pc_backtrace.size() == 1 && compare.sp_backtrace.size() == 1);
    if (this->pc_backtrace.at(0) != compare.pc_backtrace.at(0) ||
        this->sp_backtrace.at(0) != compare.sp_backtrace.at(0)) {
      return false;
    }
  } else {
    if (this->fn_backtrace != compare.fn_backtrace) {
      return false;
    }
  }
  return true;
}

/**
 * Define the inequality check between two ProcessStates as the inverse of the equity check.
 * 
 * @param compare The ProcessState that will be checked for inequality.
 * @return True if this != compare, False otherwise.
 */
bool ProcessSyscall::operator!=(const ProcessSyscall& compare) const {
  return !(*this == compare);
}

/**
 * Define the comparison mechanism that the Bimap will use to sort ProcessStates.
 * 
 * @param compare The ProcessState that will be compared with this
 * @return True if this < compare, False otherwise
 */
bool ProcessSyscall::operator<(const ProcessSyscall& compare) const {
  vector<FunctionOffset>::const_iterator it1 = this->fn_backtrace.begin();
  vector<FunctionOffset>::const_iterator it2 = compare.fn_backtrace.begin();
  if (!this->fn_backtrace.empty()) {
    while (it1 != this->fn_backtrace.end() && it2 != compare.fn_backtrace.end()) {
      if (*it1 != *it2) {
        return *it1 < *it2;
      }
      it1++;
      it2++;
    }
    if (it1 == this->fn_backtrace.end() && it2 == compare.fn_backtrace.end()) {
      return false;
    }
    // Suppose that if a stack is deeper that the other the first one comes first
    return it1 == this->fn_backtrace.end();
  } else {
    assert(this->pc_backtrace.size() == 1 && this->sp_backtrace.size() == 1);
    assert(compare.pc_backtrace.size() == 1 && compare.sp_backtrace.size() == 1);
    if (this->pc_backtrace.at(0) != compare.pc_backtrace.at(0)) {
      return this->pc_backtrace.at(0) < compare.pc_backtrace.at(0);
    } else if (this->sp_backtrace.at(0) != compare.sp_backtrace.at(0)) {
      return this->sp_backtrace.at(0) < compare.sp_backtrace.at(0);
    } else {
      return this->nsyscall < compare.nsyscall;
    }
  }
}

/**
 * This sets the syscall number, the list of call parameters and the ProcessState::regs_state pointer.
 * This is the first method to call after the ProcessState creation before the backtrace acquisition.
 * 
 * @param regs The Register object already acquired from the tracee.
 */
void ProcessSyscall::set_registers(shared_ptr<Registers> regs) {
  assert(this->regs_state == nullptr);
  assert(this->nsyscall < 0);
  assert(this->return_value == -ENOSYS);
  assert(!this->is_authorised());
  assert(this->call_param.empty());
  assert(this->fn_backtrace.empty());
  assert(this->pc_backtrace.empty());
  assert(this->sp_backtrace.empty());
  this->regs_state = regs;
  this->nsyscall = regs->nsyscall();
  this->call_param.push_back(regs->arg0());
  this->call_param.push_back(regs->arg1());
  this->call_param.push_back(regs->arg2());
  this->call_param.push_back(regs->arg3());
  this->call_param.push_back(regs->arg3());
  this->call_param.push_back(regs->arg4());
}