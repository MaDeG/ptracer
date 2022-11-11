#ifndef PTRACER_PROCESSSYSCALLEXIT_H
#define PTRACER_PROCESSSYSCALLEXIT_H

#include "ProcessNotification.h"

class ProcessSyscallExit : public ProcessNotification {
public:
	ProcessSyscallExit(std::string notificationOrigin, pid_t pid, pid_t spid, unsigned long long int returnValue);
	[[nodiscard]] unsigned long long int getReturnValue() const;
	void print() const override;
private:
	unsigned long long int returnValue;
};


#endif //PTRACER_PROCESSSYSCALLEXIT_H
