#ifndef TRACINGMANAGER_H
#define TRACINGMANAGER_H
#include "ConcurrentQueue.h"
#include "ProcessNotification.h"
#include "ProcessSyscall.h"

//extern "C" __attribute__ ((visibility ("default")))
class TracingManager {
  friend class Tracer;                                                          // Creation of a new Tracer and SPID check
public:
  static const int BUFFER_LEN;
  static bool init(std::shared_ptr<Tracer> tracer = nullptr);
  static bool start();
  static std::shared_ptr<ProcessNotification> next_notification();
  static bool authorise(std::shared_ptr<ProcessSyscall> state);
  static bool add_tracer(std::shared_ptr<Tracer> tracer);
  static bool kill_process(int spid = -1);
  static bool is_running();
  static void set_new_tracee_callback(std::function<void (pid_t, pid_t, pid_t)> child_callback);
private:
  static pid_t worker_spid;
  static ConcurrentQueue<std::shared_ptr<Tracer>> attach_wait;
  static std::map<pid_t, std::shared_ptr<Tracer>> tracers;                      // Identify a Tracer using the system-wide unique TID
  static ConcurrentQueue<std::shared_ptr<ProcessNotification>> notification_queue;
  static ConcurrentQueue<std::shared_ptr<ProcessSyscall>> authorised_tracees;
  static std::map<pid_t, std::string> possible_execves;
  static std::map<pid_t, int> possible_children;
  static std::function<void (pid_t, pid_t, pid_t)> child_callback;
  static struct sigaction authorised_action, attach_action;
  static void run();
  static bool handle_syscall(pid_t spid, int status);
  static void handle_termination(pid_t spid);
  static int handle_children(const Tracer& tracer, pid_t pid, pid_t spid);
  static void handle_execve(pid_t spid);
  static bool signalhandler_install();
  static void handle_authorised(int signal);
  static void handle_attach(int signal);
  static void add_possible_execve(int pid, std::string executable_name);
  TracingManager() = default;;
};

#endif /* TRACINGMANAGER_H */