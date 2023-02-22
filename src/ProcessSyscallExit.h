#ifndef PTRACER_PROCESSSYSCALLEXIT_H
#define PTRACER_PROCESSSYSCALLEXIT_H

#include "ProcessNotification.h"
#include "Registers.h"

class Tracer;

class ProcessSyscallExit : public ProcessNotification {
	friend class Tracer;
public:
	ProcessSyscallExit(std::string notificationOrigin, pid_t pid, pid_t spid, std::shared_ptr<Registers> regs);
	[[nodiscard]] unsigned long long int getReturnValue() const;
	[[nodiscard]] int getSyscall() const;
	void print() const override;
	[[nodiscard]] std::shared_ptr<Tracer> getTracer() const;
private:
	std::shared_ptr<Tracer> tracer;
	const std::shared_ptr<Registers> regs;
};

#endif //PTRACER_PROCESSSYSCALLEXIT_H
