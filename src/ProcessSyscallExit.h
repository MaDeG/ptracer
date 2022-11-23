#ifndef PTRACER_PROCESSSYSCALLEXIT_H
#define PTRACER_PROCESSSYSCALLEXIT_H

#include "ProcessNotification.h"
#include "Registers.h"

class ProcessSyscallExit : public ProcessNotification {
public:
	ProcessSyscallExit(std::string notificationOrigin, pid_t pid, pid_t spid, std::shared_ptr<Registers> regs);
	[[nodiscard]] unsigned long long int getReturnValue() const;
	int getSyscall() const;
	void print() const override;
private:
	const std::shared_ptr<Registers> regs;
};


#endif //PTRACER_PROCESSSYSCALLEXIT_H
