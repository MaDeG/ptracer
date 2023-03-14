#ifndef PTRACER_PROCESSSYSCALLENTRY
#define PTRACER_PROCESSSYSCALLENTRY
#include <memory>
#include <set>
#include <vector>
#include "Registers.h"
#include "ProcessNotification.h"
#include "StackFrame.h"

class TracingManager;
class Tracer;

class ProcessSyscallEntry : public ProcessNotification {
  friend class Tracer;
  friend class TracingManager;
public:
  static const std::set<int> childGeneratingSyscalls;
  static const std::set<int> exitSyscalls;
	static const std::set<int> nonReturningSyscalls;
  static const int NO_CHILD;
  static const int POSSIBLE_CHILD;
  ProcessSyscallEntry(std::string notificationOrigin, int pid, int spid);
  void print() const override;
  [[nodiscard]] unsigned long long int getPc() const;
	[[nodiscard]] unsigned long long int getSp() const;
  [[nodiscard]] int getSyscall() const;
  [[nodiscard]] long long int getReturnValue() const;
  [[nodiscard]] pid_t getChildPid() const;
  [[nodiscard]] std::shared_ptr<Tracer> getTracer() const;
	[[nodiscard]] unsigned long long int argument(unsigned short int i) const;
	[[nodiscard]] const std::vector<StackFrame>& getStackFrames() const;

private:
  std::shared_ptr<Tracer> tracer;
  long long int returnValue = -ENOSYS;
  std::shared_ptr<Registers> regs = nullptr;
	std::vector<StackFrame> stackFrames;
  pid_t childPid = -1;
  void setRegisters(std::shared_ptr<Registers> regs);
};

#endif /* PTRACER_PROCESSSYSCALLENTRY */