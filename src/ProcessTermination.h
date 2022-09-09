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
  ProcessTermination(std::string flat);
  ProcessTermination(const ProcessTermination& orig);
  ~ProcessTermination() = default;
  int get_exit_status() const;
  bool is_signaled() const;
  int get_termination_signal() const;
  bool is_coredump_generated() const;
  void print() const override;
  std::string serialize() const override;
private:
  int _waitpid_status;
  int _return_value;
};

#endif /* PROCESSTERMINATION_H */