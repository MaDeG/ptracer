#ifndef TRACER_H
#define TRACER_H
#define PERROR(message) do { \
                          perror((string(const_cast< char *>(__func__)) + \
                                  "@" + to_string(__LINE__) + \
                                  " in " + string(__FILE__) + \
                                  " -> " + message).c_str()); \
                          errno = 0; \
                        } while (false);
#include <vector>
#include <linux/limits.h>
#include <signal.h>
#include <mutex>
#include <condition_variable>
#include <boost/integer_traits.hpp>
#include "Backtracer.h"
#include "ProcessSyscall.h"
#include "Registers.h"
#include "ProcessTermination.h"
#define MAX_SYSCALL_NUMBER 313  // TODO: To be dynamically acquired from Linux kernel headers

class ProcessSyscall;

class Tracer {
  friend class TracingManager;
public:
	static const pid_t MAX_PID = boost::integer_traits<pid_t>::const_max;
  enum {
    GENERIC_ERROR = -1,          // Returned in case of a generic error not related with ptrace
    PTRACE_ERROR = -2,           // Returned when a ptrace error occurred
    UNWIND_ERROR = -3,           // Returned when a libunwind error occurred
    EXITED_ERROR = -4,           // Returned when the tracee exited in an unexpected manner.
    NOT_SPECIAL = 1,             // Returned by Tracer::handle_special_cases() when no special action are required
    SYSCALL_HANDLED = 2,         // Returned when a syscall has been successfully handled
    IMMINENT_EXIT = 3,           // Returned when the trace is going to an end and the next notification will be a child death one
    WAIT_FOR_AUTHORISATION = 4,  // Returned when a syscall entry has been received and it is waiting for authorisation
    EXECVE_SYSCALL = 5,          // Returned when an execve family syscall occurs
    REQUIRE_OPTIONS = 6          // Returned by Tracer::init() when the initialisation is not complete
  };
  Tracer(const char* program,
         char const* const* args,
         bool follow_children,
         bool follow_threads,
         bool ptrace_jail,
         bool no_backtrace);
  Tracer(const char* program,
         char const* const* args);
  Tracer(const std::string executable_name,
         pid_t spid,
         bool follow_children,
         bool follow_threads,
         bool ptrace_jail,
         bool no_backtrace,
         std::function<void ()> callback = nullptr);
  Tracer(const Tracer& tracer, const int pid, const int spid);
  ~Tracer();
  int kill_process(int signal = SIGKILL);
  std::string get_executable_name() const;
  void set_executable_name(std::string executable_name);
  bool set_attach_callback(std::function<void ()> callback);
  pid_t get_pid() const;
  pid_t get_spid() const;
  std::shared_ptr<ProcessNotification> get_current_state() const;
  bool is_tracing() const;
  int handle(int status);
  int proceed();
  int init(int status = -1);
  void set_options(bool follow_children, bool follow_threads, bool ptrace_jail, bool no_backtrace);
  void wait_for_attach();

private:
	const std::unique_ptr<Backtracer> backtracer;
  std::string _traced_executable;
  pid_t _traced_pid = -1;
  pid_t _traced_spid = -1;
  std::shared_ptr<ProcessSyscall> currentState = nullptr;
  std::shared_ptr<ProcessTermination> _termination_state = nullptr;
  bool _running = false;
  bool _attached = false;
  const char* _program = nullptr;
  char const* const* _args;
  bool _no_backtrace;
  int _ptrace_options = -1;
  const std::function<void ()> _attach_callback = nullptr;
  std::mutex _mutex;
  std::condition_variable _condition_attach;
  int exec_program();
  bool attach();
  int handle_special_cases(int status, std::shared_ptr<Registers> regs);
  int systemcall_entry(int status, std::shared_ptr<Registers> regs);
  int systemcall_exit(int status, std::shared_ptr<Registers> regs);
  int syscall_jump(std::shared_ptr<Registers> regs);
  int get_backtrace();
  int handle_execve(std::shared_ptr<Registers> regs);
  std::string extract_string(unsigned long long int address, unsigned int max_length) const;
  std::shared_ptr<siginfo_t> handle_signal(int status) const;
};

#endif // TRACER_H