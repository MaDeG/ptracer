/* 
 * File:   ProcessTermination.h
 * Author: Matteo De Giorgi
 *
 * Created on 14 January 2017, 16:43
 */

#ifndef PTRACER_PROCESSTERMINATION_H
#define PTRACER_PROCESSTERMINATION_H

#include "ProcessNotification.h"

class ProcessTermination : public ProcessNotification {
public:
  ProcessTermination(std::string notificationOrigin, int pid, int spid, int returnValue, int waitpidStatus = -1);
  [[nodiscard]] int getExitStatus() const;
  [[nodiscard]] bool isSignaled() const;
  [[nodiscard]] int getTerminationSignal() const;
  [[nodiscard]] bool isCoredumpGenerated() const;
  void print() const override;
private:
  int waitpidStatus;
  int returnValue;
};

#endif /* PTRACER_PROCESSTERMINATION_H */