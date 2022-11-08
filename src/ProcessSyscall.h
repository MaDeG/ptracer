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
  static const std::set<int> childGeneratingSyscalls;
  static const std::set<int> exitSyscalls;
  static const int NO_CHILD;
  static const int POSSIBLE_CHILD;
  ProcessSyscall(const ProcessSyscall& ps);
  ProcessSyscall();
  void print() const override;
  unsigned long long int getPc() const;
	unsigned long long int getSp() const;
  int getSyscall() const;
  long long int getReturnValue() const;
  pid_t getChildPid() const;
  std::shared_ptr<Tracer> getTracer() const;
	unsigned long long int argument(unsigned short int i) const;

private:
  std::shared_ptr<Tracer> tracer;
  long long int returnValue = -ENOSYS;
  std::shared_ptr<Registers> regs = nullptr;
	std::vector<StackFrame> stackFrames;
  //std::vector<unsigned long long int> callParams;
  pid_t childPid = -1;
  void setRegisters(std::shared_ptr<Registers> regs);
};

#endif /* PROCESSSTATE_H */