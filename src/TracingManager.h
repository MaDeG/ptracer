#ifndef PTRACER_TRACINGMANAGER_H
#define PTRACER_TRACINGMANAGER_H
#include "ConcurrentQueue.h"
#include "ProcessNotification.h"
#include "Tracer.h"

class ProcessSyscallEntry;

//extern "C" __attribute__ ((visibility ("default")))
class TracingManager {
  friend class Tracer;                                                          // Creation of a new Tracer and SPID check
public:
  static const int BUFFER_LEN;
  static bool init(std::shared_ptr<Tracer> tracer = nullptr);
  static bool start();
  static std::shared_ptr<ProcessNotification> nextNotification();
  static bool authorize(std::shared_ptr<ProcessSyscallEntry> state);
  static bool addTracer(std::shared_ptr<Tracer> tracer);
  static bool kill_process(int spid = -1);
  static bool isRunning();
  static void setNewTraceeCallback(std::function<void (pid_t, pid_t, pid_t)> child_callback);
private:
  static pid_t workerSpid;
  static ConcurrentQueue<std::shared_ptr<Tracer>> attachWait;
  static std::map<pid_t, std::shared_ptr<Tracer>> tracers;                      // Identify a Tracer using the system-wide unique TID
  static ConcurrentQueue<std::shared_ptr<ProcessNotification>> notificationQueue;
  static ConcurrentQueue<std::shared_ptr<ProcessSyscallEntry>> authorisedTracees;
  static std::map<pid_t, std::string> possibleExecves;
  static std::map<pid_t, int> possibleChildren;
  static std::function<void (pid_t, pid_t, pid_t)> childCallback;
  static struct sigaction authorised_action, attach_action;
  static void run();
  static bool handleSyscall(pid_t spid, int status);
  static void handleTermination(pid_t spid);
  static int handleChildren(const Tracer& tracer, pid_t pid, pid_t spid);
  static void handleExecve(pid_t spid);
  static bool signalhandler_install();
  static void handleAuthorised(int signal);
  static void handleAttach(int signal);
  static void addPossibleExecve(int pid, std::string executable_name);
  TracingManager() = default;;
};

#endif /* PTRACER_TRACINGMANAGER_H */