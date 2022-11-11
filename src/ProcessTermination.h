/* 
 * File:   ProcessTermination.h
 * Author: Matteo De Giorgi
 *
 * Created on 14 January 2017, 16:43
 */

#ifndef PROCESSTERMINATION_H
#define PROCESSTERMINATION_H

#include "ProcessNotification.h"

class ProcessTermination : public ProcessNotification {
public:
  ProcessTermination(std::string notification_origin, int pid, int spid, int value, int waitpid_status = -1);
  [[nodiscard]] int getExitStatus() const;
  [[nodiscard]] bool isSignaled() const;
  [[nodiscard]] int getTerminationSignal() const;
  [[nodiscard]] bool isCoredumpGenerated() const;
  void print() const override;
private:
  int waitpidStatus;
  int returnValue;
};

#endif /* PROCESSTERMINATION_H */