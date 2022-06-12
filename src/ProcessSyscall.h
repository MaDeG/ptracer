#ifndef PROCESSSTATE_H
#define PROCESSSTATE_H
#include <memory>
#include <set>
#include "Tracer.h"
#include "FunctionOffset.h"
#include "Registers.h"
#include "ProcessNotification.h"

class TracingManager;
class Tracer;

class ProcessSyscall : public ProcessNotification {
  friend class Tracer;
  friend class TracingManager;
public:
  static const std::string FIELD_SEPARATOR;
  static const std::string VALUE_SEPARATOR;
  static const std::string END_OF_OBJECT;
  static const std::set<int> child_syscalls;
  static const std::set<int> exit_syscalls;
  static const int NO_CHILD;
  static const int POSSIBLE_CHILD;
  ProcessSyscall(std::string flat, bool no_backtrace);
  ProcessSyscall(const ProcessSyscall& ps);
  ProcessSyscall();
  ~ProcessSyscall() = default;
  std::string serialize() const override;
  std::string serialize_not_minimal() const;
  void print() const override;
  long long int get_pc() const;
  int get_nsyscall() const;
  long long int get_return_value() const;
  pid_t get_child_pid() const;
  std::shared_ptr<Tracer> get_tracer() const;
  //ProcessSyscall& operator=(const ProcessSyscall&);
  bool operator==(const ProcessSyscall& compare) const;
  bool operator!=(const ProcessSyscall& compare) const;
  bool operator<(const ProcessSyscall& compare) const;

private:
  std::shared_ptr<Tracer> tracer;
  int nsyscall = -1;
  long long int return_value = -ENOSYS;
  long long int relative_pc = 0;
  std::shared_ptr<Registers> regs_state = nullptr;
  std::vector<FunctionOffset> fn_backtrace;
  std::vector<long long int> pc_backtrace;
  std::vector<long long int> sp_backtrace;
  std::vector<unsigned long long int> call_param;
  pid_t child_pid = -1;
  void set_registers(std::shared_ptr<Registers> regs);
};

#endif /* PROCESSSTATE_H */