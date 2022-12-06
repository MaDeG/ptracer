#ifndef PTRACER_TRACER_H
#define PTRACER_TRACER_H
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
#include "ProcessSyscallEntry.h"
#include "ProcessSyscallExit.h"
#include "Registers.h"
#include "ProcessTermination.h"
#define MAX_SYSCALL_NUMBER 450  // TODO: To be dynamically acquired from Linux kernel headers

class ProcessSyscallEntry;

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
         bool backtrace);
  Tracer(const char* program,
         char const* const* args);
  Tracer(const std::string executable_name,
         pid_t spid,
         bool follow_children,
         bool follow_threads,
         bool ptrace_jail,
         bool backtrace);
  Tracer(const Tracer& tracer, const int pid, const int spid);
  ~Tracer();
  int killProcess(int signal = SIGKILL);
  std::string getExecutableName() const;
  void setExecutableName(std::string executableName);
  pid_t getPid() const;
  pid_t getSpid() const;
  std::shared_ptr<ProcessNotification> getCurrentState() const;
  bool isTracing() const;
  int handle(int status);
  int proceed();
  int init(int status = -1);
  void set_options(bool follow_children, bool follow_threads, bool ptrace_jail, bool no_backtrace);
  void waitForAttach();
	std::string extractString(unsigned long long int address, unsigned int maxLength) const;
	char* extractBytes(unsigned long long int address, unsigned int maxLength) const;

private:
	static const unsigned int MAXIMUM_PROCESS_NAME_LENGTH;
	const std::unique_ptr<Backtracer> backtracer;
  std::string tracedExecutable;
  pid_t tracedPid = -1;
  pid_t tracedSpid = -1;
  std::shared_ptr<ProcessSyscallEntry> entryState = nullptr;
	std::shared_ptr<ProcessSyscallExit> exitState = nullptr;
  std::shared_ptr<ProcessTermination> terminationState = nullptr;
  bool running = false;
  bool attached = false;
  const char* program = nullptr;
  char const* const* args;
  bool backtrace;
  int ptraceOptions = -1;
  std::mutex attachMutex;
  std::condition_variable conditionAttach;
  int execProgram();
  bool attach();
  int handleSpecialCases(int status, std::shared_ptr<Registers> regs);
  int syscallEntry(int status, std::shared_ptr<Registers> regs);
  int syscallExit(int status, std::shared_ptr<Registers> regs);
  int syscallJump(std::shared_ptr<Registers> regs);
  int getBacktrace();
  int handleExecve(std::shared_ptr<Registers> regs);
  std::shared_ptr<siginfo_t> handleSignal(int status) const;
};

#endif // PTRACER_TRACER_H