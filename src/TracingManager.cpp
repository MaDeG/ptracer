#include <assert.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <thread>
#include <iostream>
#include <boost/algorithm/string.hpp>
#include "TracingManager.h"
#include "ProcessTermination.h"
#include "SyscallDecoderMapper.h"

using namespace std;

// SPID of the ptrace syscall notifications receiver
pid_t TracingManager::worker_spid = -1;
// Queue of tracers that are waiting to be initialised by the worker thread
ConcurrentQueue<shared_ptr<Tracer>> TracingManager::attach_wait;
// Global queue of notifications waiting for authorisation
ConcurrentQueue<shared_ptr<ProcessNotification>> TracingManager::notification_queue;
// Associate every traced SPID with its Tracer
map<pid_t, shared_ptr<Tracer>> TracingManager::tracers;
// Queue of states that have been authorised to proceed
ConcurrentQueue<shared_ptr<ProcessSyscallEntry>> TracingManager::authorised_tracees;
// Map of possible execve target programs, that syscall gets executed multiple times trying multiple paths.
map<pid_t, string> TracingManager::possible_execves;
// Map of statuses associated with their originator SPID that haven't an associated Tracer (yet)
map<pid_t, int> TracingManager::possible_children;
// Callback function that will be called every time a new tracee is generated.
function<void (pid_t, pid_t, pid_t)> TracingManager::child_callback = nullptr;
// Defines what to do when a SIGUSR1 is received -> Handle TracingManager::authorised_tracees queue
struct sigaction TracingManager::authorised_action;
// Defines what to do when a SIGUSR2 is received -> Handle TracingManager::attach_wait queue
struct sigaction TracingManager::attach_action;

/**
 * First method to call in order to initialise the Tracing Manager.
 * It expects parameters to set up a first Tracer that will attach to the specified SPID.
 * 
 * @param tracer            The first tracer with every parameter initialised but the syscall queue.
 * @return If this is the first initialisation returns True if the signal handler installation
 *         was successful, if this is not returns true if the passed tracer initialisation
 *         was successful, False otherwise.
 */
bool TracingManager::init(shared_ptr<Tracer> tracer) {
  if (tracer != nullptr) {
    TracingManager::attach_wait.push(tracer);
  }
  if (TracingManager::tracers.empty()) {
    return TracingManager::signalhandler_install();
  }
  return true;
}

/**
 * This is the first method to call, it starts the first tracer thread.
 * After this call the first ProcessState (the execve syscall) will be the first element in
 * the syscall queue.
 * 
 * @return True if the TracingManager worker thread was correctly started, False if it
 *         has already been started.
 */
bool TracingManager::start() {
  if (TracingManager::worker_spid > 0) {
    return false;
  }
  assert(TracingManager::tracers.empty());
  thread* new_thread = new thread(&TracingManager::run);
  new_thread->detach();
  return true;
}

/**
 * Returns the first notification in the queue shared among all tracers.
 * If the queue is empty it will hang until a notification arrives.
 * 
 * @return A reference to the first ProcessState in the queue.
 */
shared_ptr<ProcessNotification> TracingManager::next_notification() {
  return TracingManager::notification_queue.pop();
}

/**
 * Method called only by ProcessState::authorise in order to unblock the tracer of SPID
 * until the next syscall.
 * This will send a SIGUSR1 signal to the worker thread that will be stopped in order to
 * handle the queue of authorised tracees.
 * 
 * @param spid The process SPID or (Thread ID) that will be authorised to proceed.
 * @return True if the syscall has already been authorised or the worker thread was successfully notified, False otherwise.
 */
bool TracingManager::authorise(shared_ptr<ProcessSyscallEntry> state) {
  if (!state->authorise()) {
		// Already authorised
		return true;
	}
  assert(TracingManager::worker_spid > 0 && TracingManager::worker_spid < Tracer::MAX_PID);
  assert(TracingManager::worker_spid != syscall(SYS_gettid));
  if (state == nullptr) {
    return true;
  }
  TracingManager::authorised_tracees.push(state);
  if (syscall(SYS_tkill, TracingManager::worker_spid, SIGUSR1)) {
    PERROR("Cannot send a SIGUSR1 signal to " + to_string(TracingManager::worker_spid));
    return false;
  }
  return true;
}

/**
 * Used to add a new Tracer that will be initialised and then managed.
 * If the insertion fail it means that it was not possible to deliver a SIGUSR2
 * to the worker thread.
 * 
 * @param tracer The Tracer that will be added.
 * @return True if the insertion was successful, False otherwise.
 */
bool TracingManager::add_tracer(shared_ptr<Tracer> tracer) {
  assert(TracingManager::worker_spid > 0 && TracingManager::worker_spid < Tracer::MAX_PID);
  assert(TracingManager::worker_spid != syscall(SYS_gettid));
  assert(tracer != nullptr);
  if (TracingManager::tracers.empty()) {
    // TracingManager::run() will take care of this Tracer
    TracingManager::attach_wait.push(tracer);
    return true;
  }
  TracingManager::attach_wait.push(tracer);
  if (syscall(SYS_tkill, TracingManager::worker_spid, SIGUSR2)) {
    PERROR("Cannot send a SIGUSR2 signal to " + to_string(TracingManager::worker_spid));
    return false;
  }
  return true;
}

/**
 * Kill every Tracee.
 * It may be called by the Authoriser if an unexpected syscall occurs.
 * 
 * @param spid The SPID that will be killed, if it is a negative number every tracee will be killed.
 * @return True if all the SIGKILL signals were successful delivered, False otherwise.
 */
bool TracingManager::kill_process(int spid) {
  assert(TracingManager::worker_spid > 0 && TracingManager::worker_spid < Tracer::MAX_PID);
  bool return_value = true;
  if (spid > 0) {
    if (TracingManager::tracers.find(spid) == TracingManager::tracers.end()) {
      return false;
    }
    return TracingManager::tracers[spid]->killProcess();
  }
  for (auto& i : TracingManager::tracers) {
    return_value = (i.second)->killProcess();
  }
  return return_value;
}

/**
 * Tells if there is at least one running Tracee or not.
 * 
 * @return True if the tracing is active, False otherwise.
 */
bool TracingManager::is_running() {
  return !TracingManager::tracers.empty();
}

/**
 * Sets a callback function that will be called every time a new tracee is generated.
 * The callback function will receive: father SPID, child PID, child SPID.
 * 
 * @param child_callback The function that will be called every new tracee.
 */
void TracingManager::set_new_tracee_callback(function<void (pid_t, pid_t, pid_t)> child_callback) {
  TracingManager::child_callback = child_callback;
}

/**
 * Worker thread entry point.
 * This method waits for a notification from any tracee and then (according to the Thread ID)
 * delegates to the associated Tracer to handle this signal.
 * When no more ProcessStates will be pushed in the global syscall queue a nullptr will be inserted in
 * order to notify the event.
 */
void TracingManager::run() {
  pid_t spid;
  int status;
  TracingManager::worker_spid = (pid_t) syscall(SYS_gettid);
  shared_ptr<Tracer> first;
  do {
    first = TracingManager::attach_wait.pop();
  } while (first->init());
  assert(first->getSpid() > 0 && first->getSpid() < Tracer::MAX_PID);
  TracingManager::tracers[first->getSpid()] = move(first);
  do {
    spid = waitpid(-1, &status, __WALL);
    if (spid < 0) {
      PERROR("Waitpid error");
      if (!TracingManager::kill_process()) {
        cout << "Error occurred while trying to kill one or more tracees" << endl;
      }
      break;
    }
		if (!WIFSTOPPED(status)) {
			cout << "Received signal not coming from ptrace" << endl;
		} else if (!WIFEXITED(status)) {
      if (!TracingManager::handle_syscall(spid, status)) {
        break;
      }
    } else {
      if (TracingManager::tracers.find(spid) != TracingManager::tracers.end()) {
        // Ptrace does not guarantee to always deliver a termination notification
        TracingManager::tracers[spid]->handle(status);
        TracingManager::handle_termination(spid);
      }
      cout << "Termination notification from child SPID: " << spid << endl;
    }
  } while (!TracingManager::tracers.empty());
  if (!TracingManager::possible_children.empty()) {
    cout << "The following SPID has sent a notification but there was NOT a Tracer ready for them: ";
    for (auto& i : TracingManager::possible_children) {
      cout << i.first << "  ";
    }
  }
  TracingManager::notification_queue.push(nullptr);
  if (!TracingManager::possible_children.empty()) {
    cout << "There are received statuses that have not been matched with any traced thread: " << endl;
    for (auto& i : TracingManager::possible_children) {
      cout << "Received from SPID: " << i.first << " status: " << i.second << endl;
    }
  }
}

/**
 * Handles a ProcessSyscall received by the Tracer of spid with status as waitpid value.
 * 
 * @param spid   The SPID that has generated this syscall.
 * @param status The waitpid status received.
 * @return True if the syscall handle was successfull, False if an error occurred.
 */
bool TracingManager::handle_syscall(pid_t spid, int status) {
  if (TracingManager::tracers.find(spid) == TracingManager::tracers.end()) {
    cerr << "Impossible to find a Tracer for SPID " << spid << endl;
    cerr << "The status received will be stored" << endl;
    TracingManager::possible_children[spid] = status;
    return true;
  }
  int t;
  switch (t = TracingManager::tracers[spid]->handle(status)) {
    case 0:
      // System call exit managed
      break;
    case Tracer::WAIT_FOR_AUTHORISATION:
			// TODO: The if below should not be here
			if (TracingManager::tracers[spid]->entryState) {
				SyscallDecoderMapper::decode(*TracingManager::tracers[spid]->entryState);
			} else if (TracingManager::tracers[spid]->exitState) {
			  SyscallDecoderMapper::decode(*TracingManager::tracers[spid]->exitState);
		  }
      TracingManager::notification_queue.push(TracingManager::tracers[spid]->getCurrentState());
      break;
    case Tracer::EXECVE_SYSCALL:
      TracingManager::handle_execve(spid);
      break;
    case Tracer::IMMINENT_EXIT:
      TracingManager::handle_termination(spid);
      break;
    case Tracer::EXITED_ERROR:
      cout << "Impossible to let the tracee SPID " << spid << " proceed since it is not running" << endl;
      break;
    default:
      cout << "Unrecoverable error detected!" << endl;
      cout << "Every tracee will be killed!" << endl;
      if (!TracingManager::kill_process()) {
        cout << "Error occurred while trying to kill one or more tracees" << endl;
      }
      return false;
  }
  return true;
}

/**
 * Handles the termination of a Tracer erasing it from the global map.
 * 
 * @param spid   The SPID which is terminating.
 * @param status The termination status of spid.
 */
void TracingManager::handle_termination(pid_t spid) {
  assert(spid > 0 && spid < Tracer::MAX_PID);
  assert(TracingManager::tracers.find(spid) != TracingManager::tracers.end());
  assert(!TracingManager::tracers[spid]->isTracing());
  if (dynamic_pointer_cast<ProcessTermination>(TracingManager::tracers[spid]->getCurrentState()) == nullptr) {
    //TracingManager::tracers[spid]->get_current_state()->print();
  }
  TracingManager::notification_queue.push(TracingManager::tracers[spid]->getCurrentState());
  // Ptrace does not guarantee that a thread exit notification is always delivered
  if (TracingManager::tracers.erase(spid) != 1) {
    cerr << "Impossible to delete the SPID " << spid << " Tracer" << endl;
  }
}

/**
 * Handle the creation of a new Tracer in order to trace a child (Thread or Process) of an 
 * existing Tracer.
 * 
 * @param tracer The Tracer that is requesting the tracing of a child.
 * @param pid     The PID of the new thread to trace.
 * @param spid   The SPID of the new thread to trace.
 * @return Returns: 0 if the new Tracer initialisation was successful.
 *                  Tracer::EXITED_ERROR if the tracee is already going to an end, it has not been correctly started.
 *                  Tracer::PTRACE_ERROR if a ptrace error occurred.
 *                  Tracer::UNWIND_ERROR if a libunwind initialisation error occurred.
 *                  Tracer::GENERIC_ERRO if an error occurred during the PIDs namespace conversion.
 */
int TracingManager::handle_children(const Tracer& tracer, pid_t pid, pid_t spid) {
  assert(TracingManager::worker_spid == syscall(SYS_gettid));
  assert(tracer.entryState != nullptr);
  int status;
  TracingManager::tracers[spid] = make_unique<Tracer>(tracer, pid, spid);
  if (TracingManager::child_callback != nullptr) {
    TracingManager::child_callback(tracer.getSpid(), pid, spid);
  }
  if (TracingManager::possible_children.find(spid) != TracingManager::possible_children.end()) {
    status = TracingManager::possible_children[spid];
    TracingManager::possible_children.erase(spid);
    return TracingManager::tracers[spid]->init(status);
  }
  return TracingManager::tracers[spid]->init();
}

/**
 * Handles the case of an execve syscall so it changes the executable name of the pid thread
 * leader since it will be the only active thread after this syscall and resets its internal state.
 * Then every Tracer that is not the thread group leader will be deleted.
 * 
 * @param pid The PID of the thread group which executed an execve.
 */
void TracingManager::handle_execve(pid_t spid) {
  assert(TracingManager::possible_execves.find(spid) != TracingManager::possible_execves.end());
  assert(!TracingManager::possible_execves[spid].empty() && TracingManager::possible_execves[spid].size() < PATH_MAX);
  int pid_to_reset = TracingManager::tracers[spid]->getPid();
	TracingManager::tracers[spid]->setExecutableName(TracingManager::possible_execves[spid]);
  TracingManager::tracers[spid]->entryState = nullptr;
  TracingManager::tracers[spid]->terminationState = nullptr;
  cout << "The tracee for PID " << spid << " is changing executable file in " << TracingManager::possible_execves[spid] << " due to an execve" << endl;
  for (auto& i : TracingManager::tracers) {
    assert(i.first == i.second->getSpid());
    // After an execve syscall only the thread group leader will be active so the one with PID == SPID
    if (i.second->getPid() == pid_to_reset && i.second->getPid() != i.second->getSpid()) {
      if (TracingManager::tracers.erase(i.second->getSpid()) != 1) {
        cerr << "Impossibile to delete the SPID " << i.second->getSpid() << " Tracer after an execve syscall" << endl;
      }
    }
  }
}

/**
 * Installs:
 * - SIGUSR1 signal handler in order to receive the syscall authorisation notification.
 * - SIGUSR2 signal handler in order to manage the arrival of a new Tracer.
 * 
 * 
 * @return True if the signal was correctly installed, False otherwise.
 */
bool TracingManager::signalhandler_install() {
  TracingManager::authorised_action.sa_handler = &TracingManager::handle_authorised;
  if (sigemptyset(&TracingManager::authorised_action.sa_mask)) {
    PERROR("Impossible to set the signal handler mask for SIGUSR1");
    return false;
  }
  TracingManager::authorised_action.sa_flags = SA_RESTART;
  if (sigaction(SIGUSR1, &TracingManager::authorised_action, nullptr)) {
    PERROR("Impossible to install the signal handler for SIGUSR1");
    return false;
  }
  TracingManager::attach_action.sa_handler = &TracingManager::handle_attach;
  if (sigemptyset(&TracingManager::attach_action.sa_mask)) {
    PERROR("Impossible to set the signal handler mask for SIGUSR2");
    return false;
  }
  TracingManager::attach_action.sa_flags = SA_RESTART;
  if (sigaction(SIGUSR2, &TracingManager::attach_action, nullptr)) {
    PERROR("Impossible to install the signal handler for SIGUSR2");
    return false;
  }
  return true;
}

/**
 * This is the signal handler that is called every time a SIGUSR1 is received therefore
 * it is called every time a new syscall is authorised by the Authoriser.
 * It will iterate over the authorised tracees queue and for each element will authorise
 * the linked Tracer to proceed until the next syscall.
 * 
 * @param signal The signal that has triggered the execution of this method.
 */
void TracingManager::handle_authorised(int signal) {
  assert(TracingManager::worker_spid == syscall(SYS_gettid));
  assert(signal == SIGUSR1);
  shared_ptr<ProcessSyscallEntry> current_state;
  while (TracingManager::authorised_tracees.try_pop(current_state)) {
    if (current_state->getTracer() == nullptr) {
      cout << "Impossible to find a Tracer for state: " << endl;
      current_state->print();
      continue;
    }
    current_state->authorise();
    if (current_state->getTracer()->proceed() == Tracer::PTRACE_ERROR) {
      cerr << "Impossible to successfully authorise the state: " << endl;
      current_state->print();
    }
  }
}

/**
 * This is the signal handler that is called every time a SIGUSR2 is received therefore
 * it is called every time a new tracer wants to be initialised.
 * This is necessary since every Ptrace operation must happen in the same thread.
 * 
 * @param signal The signal that has triggered the execution of this method
 */
void TracingManager::handle_attach(int signal) {
  assert(TracingManager::worker_spid == syscall(SYS_gettid));
  assert(signal == SIGUSR2);
  assert(!TracingManager::attach_wait.empty());
  shared_ptr<Tracer> tracer;
  while (TracingManager::attach_wait.try_pop(tracer)) {
    assert(tracer->getSpid() > 0 && tracer->getSpid() < Tracer::MAX_PID);
    if (tracer->init()) {
      cerr << "Error during Tracer for SPID " << tracer->getSpid() << " initialisation" << endl;
      continue;
    }
    assert(tracer->isTracing());
    TracingManager::tracers[tracer->getSpid()] = tracer;
  }
}

/**
 * Adds a new possible executable name for an execve syscall entry that has been received.
 * That execve may fail but if it succeed TracingManager::run will expect to find the new
 * executable name in TracingManager::possible_execves.
 *
 * @param pid             The PID where the execve syscall took place.
 * @param executable_name The new executable name extracted from the tracee memory.
 */
void TracingManager::add_possible_execve(int pid, string executable_name) {
  TracingManager::possible_execves[pid] = executable_name;
  cout << "Possible execve for pid " << pid << ": " << executable_name << endl;
}