/* 
 * File:   Tracer.cpp
 * Author: Matteo De Giorgi
 *
 * A Tracer can execute a new process given its executable path and arguments, in order 
 * to do so the method Tracer::init() must always be called at the beginning.
 * Then the wait for authorisation logic can be implemented calling Tracer::handle() and 
 * then proceed when the syscall contained in Tracer::current_state is authorised to be executed.
 * Two subsequent Tracer::handle() or Tracer::proceed() methods invocation must never occur.
 * All the ptrace operation on the Tracee must be performed on the same thread.
 * A ProcesState return value can be acquired only after a Tracer::proceed() call.
 * The word SPID is the same as TID (Thread ID) or LWP (Lightweight Process).
 * The possible errors are:
 * Tracer::GENERIC_ERROR: When an error not linked with ptrace occur.
 * Tracer::PTRACE_ERROR:  When ptrace cannot do an operation, this implies the immediate tracing interruption.
 * Tracer::UNWIND_ERROR:  When an error with libunwind occurred.
 * Tracer::EXITED_ERROR:  When the tracee has generated a child death notification (WIFEXITED()) in an unexpected point.
 */

#include <unistd.h>
#include <assert.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <stddef.h>
#include <signal.h>
#include <vector>
#include <iostream>
#include <string.h>
#include <ios>
#include <memory>
#include <asm/unistd_64.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <future>
#include "Launcher.h"
#include "Tracer.h"
#include "TracingManager.h"

using namespace std;

const string Tracer::FIELD_SEPARATOR = " ";
const string Tracer::END_OF_OBJECT = "\n";

/**
 * Construct a Tracer that will exec a new traced process according to the provided parameters.
 * 
 * @param program         The tracee executable path.
 * @param args            The nullptr terminated array of string parameters to pass to the tracee.
 * @param follow_children If True also the child processes of the tracee will be traced.
 * @param follow_threads  If True also the child Threads of the tracee will be traced.
 * @param ptrace_jail     If True in case of a Tracer crash the Tracee will be automatically killed by ptrace.
 * @param no_backtrace    If true libunwind will not be used and a syscall will be identified by PC and SP.
 */
Tracer::Tracer(const char* program,
               char const* const* args,
               bool follow_children,
               bool follow_threads,
               bool ptrace_jail) : _program(program),
							                     _args(args),
                                   _attach_callback(nullptr) {
	assert(program != nullptr);
	assert(!strncmp(_args[0], _program, PATH_MAX));
	this->_traced_executable = string(program);
	this->_ptrace_options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXIT | PTRACE_O_TRACEEXEC;
	if (follow_children) {
		// Receive an extra notification just before a fork/vfork syscall.
		this->_ptrace_options |= PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
	}
	if (follow_threads) {
		// Receive an extra notification just before a clone syscall.
		this->_ptrace_options |= PTRACE_O_TRACECLONE;
	}
	if (ptrace_jail) {
		// Send a SIGKILL if the tracer process dies.
		this->_ptrace_options |= PTRACE_O_EXITKILL;
	}
	this->_running = false;
	this->_attached = false;
}

/**
 * Construct a Tracer that will exec and attach to the provided process and then
 * before proceeding will need the ptrace options specification.
 * 
 * @param program         The tracee executable path.
 * @param args            The nullptr terminated array of string parameters to pass to the tracee.
 */
Tracer::Tracer(const char* program, const char* const* args) : _program(program),
                                                               _args(args),
                                                               _attach_callback(nullptr) {
	assert(program != nullptr);
	assert(!strncmp(_args[0], _program, PATH_MAX));
	this->_traced_executable = string(program);
	this->_running = false;
	this->_attached = false;
}

/**
 * Construct a Tracer that will attach to an existing thread.
 * Keep in mind that the real tracing will start only after an execve notification.
 *
 * @param executable_name The tracee executable name or path.
 * @param spid            The tracee PID assigned by the guest system.
 * @param follow_children If True also the child processes of the tracee will be traced.
 * @param follow_threads  If True also the child Threads of the tracee will be traced.
 * @param ptrace_jail     If True in case of a Tracer crash the Tracee will be automatically killed by ptrace.
 * @param container_id    If not empty it will be used to translate the retrieved PIDs to the host namespace
 * @param callback        A function that will be called just after being attached to the tracee.
*/
Tracer::Tracer(const string executable_name,
               pid_t spid,
               bool follow_children,
               bool follow_threads,
               bool ptrace_jail,
               function<void ()> callback) : _attach_callback (callback) {
	assert(!executable_name.empty());
	assert(spid > 0 && spid < MAX_PID);
	this->_traced_executable = executable_name;
	// They will surely be the same since we begin to trace from the first execve call
	this->_traced_pid = spid;
	this->_traced_spid = spid;
	this->_running = true;
	this->_ptrace_options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXIT | PTRACE_O_TRACEEXEC;
	if (follow_children) {
		// Receive an extra notification just before a fork/vfork syscall.
		this->_ptrace_options |= PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
	}
	if (follow_threads) {
		// Receive an extra notification just before a clone syscall.
		this->_ptrace_options |= PTRACE_O_TRACECLONE;
	}
	if (ptrace_jail) {
		// Send a SIGKILL if the tracer process dies.
		this->_ptrace_options |= PTRACE_O_EXITKILL;
	}
}

/**
 * Kind of copy constructor that given an existing running tracer copy its parameter except for
 * the traced SPID and initialisation parameters of libunwind which will be recreated.
 * 
 * @param tracer A reference to the existing running tracer that will be cloned.
 * @param pid    The PID of the new thread the will be traced.
 * @param spid   The SPID of the thread that will be traced.
 */
Tracer::Tracer(const Tracer& tracer, const int pid, const int spid) : _traced_executable(tracer._traced_executable),
                                                                      _program(tracer._program),
                                                                      _args(tracer._args),
                                                                      _ptrace_options(tracer._ptrace_options),
                                                                      _attach_callback(nullptr) {
	assert(pid > 0 && pid < Tracer::MAX_PID);
	assert(spid > 0 && spid < Tracer::MAX_PID);
	assert(pid != spid || (tracer._ptrace_options & (PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK)));
	assert(pid == spid || (tracer._ptrace_options & PTRACE_O_TRACECLONE));
	assert(!tracer._traced_executable.empty());
	this->_traced_pid = pid;
	this->_traced_spid = spid;
	this->_running = true;
	this->_attached = true;
}

/**
 * Kill the tracee with a default SIGKILL or a specified signal number.
 * 
 * @param signal Defaults to SIGKILL (forcedly kill the tracee) but can be manually modified.
 * @return Returns: 0 if the signal delivery was successful.
 *                  Tracer::GENERIC_ERROR if the kill call fails.
 */
int Tracer::kill_process(int signal) {
	assert(this->_traced_spid > 0 && this->_traced_spid < Tracer::MAX_PID);
	assert(this->_traced_pid > 0 && this->_traced_pid < Tracer::MAX_PID);
	if (!this->_running) {
		cout << "The tracee PID " << this->_traced_pid << " SPID " << this->_traced_spid << " is already dead" << endl;
	}
	cout << "Killing traced thread PID " << this->_traced_pid << " SPID " << this->_traced_spid << endl;
	errno = 0;
	kill(this->_traced_spid, signal);
	if (errno) {
		PERROR("Error occurred during process SPID " + to_string(this->_traced_spid) + " signal " + to_string(signal) + " delivery");
		return Tracer::GENERIC_ERROR;
	}
	cout << "Process SPID " << to_string(this->_traced_spid) << " has received a signal number " + to_string(signal) << endl;
	return 0;
}

/**
 * Gets the executable name which is running on this PID.
 * 
 * @return The tracee executabe name.
 */
string Tracer::get_executable_name() const {
	assert(!this->_traced_executable.empty());
	return this->_traced_executable;
}

/**
 * Sets a new executable name for this tracee.
 * This can happen ONLY in case of an execve syscall.
 * 
 * @param executable_name The new executable name with or without path.
 */
void Tracer::set_executable_name(string executable_name) {
	assert(!executable_name.empty());
	assert(executable_name.size() < PATH_MAX);
	this->_traced_executable = executable_name;
}

/**
 * It gets the current active state or the termination state if the tracee is already terminated.
 * If this Tracee is not stopped at a syscall this will return nullptr.
 * The syscall return value will be -ENOSYS until the syscall exit is performed then it will take the
 * real return value.
 * 
 * @return The current active state or or the termination state if the tracee is already terminated.
 */
shared_ptr<ProcessNotification> Tracer::get_current_state() const {
	assert((this->_current_state != nullptr && this->is_tracing()) ||
	       (this->_termination_state != nullptr && !this->is_tracing()));
	assert((this->_current_state != nullptr) ^ (this->_termination_state != nullptr));
	if (this->_current_state != nullptr) {
		return this->_current_state;
	}
	return this->_termination_state;
}

/**
 * Gets the current Tracer status: If the tracee is running and we are attached via ptrace,
 * it means that everything is ready to receive syscall notifications.
 * 
 * @return True if the Tracee is running and we are attached to it.
 */
bool Tracer::is_tracing() const {
	return this->_running && this->_attached;
}

/**
 * It gets the tracee PID that identify a thread group.
 * The PID is system wide unique.
 * 
 * @return The tracee PID.
 */
pid_t Tracer::get_pid() const {
	assert(this->_traced_pid > 0 && this->_traced_spid < Tracer::MAX_PID);
	assert(this->_traced_pid > 0 && this->_traced_pid < Tracer::MAX_PID);
	return this->_traced_pid;
}

/**
 * It gets the tracee SPID (or Thread ID) identifier.
 * The SPID is system wide unique.
 * 
 * @return The tracee SPID.
 */
pid_t Tracer::get_spid() const {
	assert(this->_traced_spid > 0 && this->_traced_spid < Tracer::MAX_PID);
	assert(this->_traced_pid > 0 && this->_traced_pid < Tracer::MAX_PID);
	return this->_traced_spid;
}

/**
 * This is called by TracingManager::run when a notification from this->tracer_spid arrives.
 * If the current state is nullptr Tracer::syscall_entry() is called in order to acquire 
 * all the syscall information and craft the new ProcessState that will be taken by the TracingManager.
 * If the current state is not nullptr Tracer::syscall_exit() is called in order to manage the syscall exit
 * and assign a value to the current state return value.
 * 
 * @param status The status variable of the waitpid call that have received the sysentry notification.
 * @return Returns: 0                      If the Tracee is still alive and will produce at least another notification.
 *                  Tracer::IMMINENT_EXIT  If the Tracee is going to die.
 *                  Tracer::EXECVE_SYSCALL If an execve syscall is going to be performed. 
 *                  Tracer::PTRACE_ERROR   If a ptrace error occurred while trying to retrieve the tracee registers.
 *                  Tracer::UNWIND_ERROR   If an error occurred while trying to retrieve the syscall backtrace.
 *                  Tracer::EXITED_ERROR   If the traced thread is not running.
 */
int Tracer::handle(int status) {
	assert(TracingManager::worker_spid == syscall(SYS_gettid));
	assert(this->_traced_spid > 0 && this->_traced_spid < Tracer::MAX_PID);
	assert(this->_traced_pid > 0 && this->_traced_pid < Tracer::MAX_PID);
	if (WIFEXITED(status)) {
		this->_running = false;
		this->_attached = false;
		if (this->_current_state != nullptr) {
			cout << "The following system call will never be completed:" << endl;
			this->_current_state->print();
			this->_current_state = nullptr;
		}
		this->_termination_state = make_shared<ProcessTermination>(this->get_executable_name(),
		                                                           this->_traced_pid,
		                                                           this->_traced_spid,
		                                                           WEXITSTATUS(status),
		                                                           status);
		return EXITED_ERROR;
	}
	shared_ptr<Registers> regs = make_shared<Registers>();
	int return_value;
	if (!this->_running && status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) { // If this tracee is back from the death
		this->_running = true;
		this->_attached = true;
		this->handle_execve(regs);
		assert(regs->nsyscall() == SYS_execve);
		assert(!regs->ret_arg());
		if (ptrace(PTRACE_SYSCALL, this->_traced_spid, nullptr, 0)) {
			PERROR("Ptrace error while trying to proceed from an execve exit notification of SPID " + to_string(this->_traced_spid));
			return Tracer::PTRACE_ERROR;
		}
		this->_current_state = nullptr;
		this->_termination_state = nullptr;
		return Tracer::EXECVE_SYSCALL;
	}
	if (!this->_running) {
		if (ptrace(PTRACE_SYSCALL, this->_traced_spid, nullptr, 0)) {
			PERROR("Ptrace error occurred while trying to continue from a special caseof SPID " + to_string(this->_traced_spid));
			return Tracer::PTRACE_ERROR;
		}
		return Tracer::EXITED_ERROR;
	}
	assert(this->_termination_state == nullptr);
	switch (return_value = this->handle_special_cases(status, regs)) {
		case Tracer::SYSCALL_HANDLED:
			if (ptrace(PTRACE_SYSCALL, this->_traced_spid, nullptr, 0)) {
				PERROR("Ptrace error occurred while trying to continue from a special caseof SPID " + to_string(this->_traced_spid));
				return Tracer::PTRACE_ERROR;
			}
			this->_current_state = nullptr;
			return 0;
			break;
		case Tracer::EXECVE_SYSCALL:
			if (!this->systemcall_exit(status, regs)) {
				return return_value;
			}
			return Tracer::PTRACE_ERROR;
			break;
		case Tracer::IMMINENT_EXIT:
			if (ptrace(PTRACE_SYSCALL, this->_traced_spid, nullptr, 0)) {
				PERROR("Ptrace error while trying to proceed from a termination notification of SPID " + to_string(this->_traced_spid));
				return Tracer::PTRACE_ERROR;
			}
			return return_value;
			break;
		case Tracer::NOT_SPECIAL:
			break;
		default:
			return return_value;
			break;
	}
	if (!WIFSTOPPED(status) || WSTOPSIG(status) != (SIGTRAP | 0x80)) {
		if (this->handle_signal(status) == nullptr) {
			return Tracer::PTRACE_ERROR;
		}
		return 0;
	}
	if (this->_current_state == nullptr) {
		return this->systemcall_entry(status, regs);
	} else {
		return this->systemcall_exit(status, regs);
	}
}

/**
 * Authorise the Tracee to proceed until the next System call.
 *
 * @return Returns: 0 If there were no errors.
 *                  Tracer::PTRACE_ERROR If a ptrace error occurred.
 *                  Tracer::GENERIC_ERROR If this tracee is dead or it is not waiting for a green light.
 */
int Tracer::proceed() {
	assert(TracingManager::worker_spid == syscall(SYS_gettid));
	assert(this->_traced_spid > 0 && this->_traced_spid < Tracer::MAX_PID);
	assert(this->_traced_pid > 0 && this->_traced_pid < Tracer::MAX_PID);
	if (!this->_running) {
		cerr << "Impossible to let a dead tracee proceed! Tracee SPID: " << this->_traced_spid << endl;
		return Tracer::GENERIC_ERROR;
	} else if (!this->_attached) {
		cerr << "Impossible to let a not attached tracee proceed! Tracee SPID: " << this->_traced_spid << endl;
		return Tracer::GENERIC_ERROR;
	}
	assert(this->_current_state != nullptr);
	assert(this->_current_state->_authorised);
	if (ptrace(PTRACE_SYSCALL, this->_traced_spid, nullptr, 0)) {
		PERROR("Ptrace error occurred while trying to continue from the syscall number " + to_string(this->_current_state->nsyscall) +
		       " entry notification in SPID " + to_string(this->_traced_spid));
		return Tracer::PTRACE_ERROR;
	}
	return 0;
}

/**
 * Initialize the Tracer: Starts the tracee according to program and args if a SPID has not been provided,
 * otherwise performs an attach to the already running tracee.
 * After this method call the variable SPID contains the tracee SPID.
 * Set the correct ptrace options according to the desidered behaviour (trace child threads or processes) and
 * take care of the first syscall.
 * 
 * @param status An already acquired status from a waitpid call, if not specified it will be acquired.
 * @return Returns: 0 if the initialisation was successful.
 *                  Tracer::REQUIRE_OPTIONS If the initialisation is not complete due to missing ptrace options.
 *                  Tracer::EXITED_ERROR    If the tracee is already going to an end, it has not been correctly started.
 *                  Tracer::PTRACE_ERROR    If a ptrace error occurred.
 *                  Tracer::UNWIND_ERROR    If a libunwind initialisation error occurred.
 *                  Tracer::GENERIC_ERROR   If a waitpid or child execution error occurs.
 */
int Tracer::init(int status) {
	pid_t pid;
	if (!this->_attached) {
		if (this->_running) {
			if (!this->attach()) {
				return Tracer::PTRACE_ERROR;
			}
		} else if (this->exec_program()) {
			return Tracer::GENERIC_ERROR;
		}
	}
	assert(this->_attached && this->_running);
	// If this Tracer is already tracing means that this is a second initialisation
	if (this->_ptrace_options >= 0 && status < 0) {
		do {
			// Waiting for tracee sys_exec notification
			pid = waitpid(this->_traced_spid, &status, __WALL);
			if (pid < 0) {
				PERROR("Waitpid error while waiting for child " + to_string(this->_traced_spid));
				return Tracer::GENERIC_ERROR;
			}
			assert(this->_traced_spid == pid);
			if (WIFEXITED(status)) {
				return Tracer::EXITED_ERROR;
			}
		} while (!WIFSTOPPED(status) || (WSTOPSIG(status) != SIGSTOP && WSTOPSIG(status) != SIGTRAP));
	}
	if (this->_ptrace_options < 0) {
		// Tracer::set_options() will take care of the following part when called
		cout << "Tracer for SPID " << this->_traced_spid << " set options deferred" << endl;
		return Tracer::REQUIRE_OPTIONS;
	}
	if (ptrace(PTRACE_SETOPTIONS, this->_traced_spid, nullptr, this->_ptrace_options)) {
		PERROR("Ptrace error occurred while trying to do a SETOPTIONS to SPID " + to_string(this->_traced_spid));
		return Tracer::PTRACE_ERROR;
	}
#ifndef NDEBUG
	Registers regs;
	if (ptrace(PTRACE_GETREGS, this->_traced_spid, nullptr, &regs)) {
		PERROR("Ptrace error occurred while trying to GETREGS on the first system call of SPID " + to_string(this->_traced_spid));
		return Tracer::PTRACE_ERROR;
	}
	//cout << "Tracer SPID: " << this->_traced_spid << " first syscall number: " << regs.nsyscall() << " return: " << regs.ret_arg() << endl;
#endif
	// Entry notification received, go ahead
	if (ptrace(PTRACE_SYSCALL, this->_traced_spid, nullptr, 0)) {
		PERROR("Ptrace error occurred while trying to SYSCALL after the first system call of SPID " + to_string(this->_traced_spid));
		return Tracer::PTRACE_ERROR;
	}
	return 0;
}

/**
 * Sets the PTRACE options according with the passed prameters.
 * 
 * @param follow_children If specified every generated children (generation of a new PID) will be traced.
 * @param follow_threads  If specified every generated thread (generation of a new SPID, same PID) will be traced.
 * @param ptrace_jail     If specified when the tracer dies a SIGKILL is delivered to the tracee.
 */
void Tracer::set_options(bool follow_children, bool follow_threads, bool ptrace_jail) {
	assert(this->_ptrace_options < 0);
	// Set stop signal that we will receive to: SIGTRAP | 0x80 and receive a notification just before the tracee exit
	this->_ptrace_options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXIT | PTRACE_O_TRACEEXEC;
	if (follow_children) {
		// Receive an extra notification just before a fork/vfork syscall.
		this->_ptrace_options |= PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
	}
	if (follow_threads) {
		// Receive an extra notification just before a clone syscall.
		this->_ptrace_options |= PTRACE_O_TRACECLONE;
	}
	if (ptrace_jail) {
		// Send a SIGKILL if the tracer process dies.
		this->_ptrace_options |= PTRACE_O_EXITKILL;
	}
}

/**
 * Defines the Tracer serialised flat string.
 * 
 * @return The tracer flat representation.
 */
string Tracer::serialize() const {
	string result;
	result = this->_traced_executable + Tracer::FIELD_SEPARATOR;
	result += to_string(this->_traced_pid) + Tracer::FIELD_SEPARATOR;
	result += to_string(this->_traced_spid);
	result += Tracer::END_OF_OBJECT;
	return result;
}

/**
 * Hangs until the current Tracer is attached to its tracee by the TracingManager
 * worker thread.
 */
void Tracer::wait_for_attach() {
	unique_lock<mutex> lock(this->_mutex);
	while (!this->_attached) {
		this->_condition_attach.wait(lock);
	}
}


/**
 * Execute the program specified in Tracer::program with Tracer::args array as nullptr terminated
 * string of arguments.
 * 
 * @return Returns: 0 if the fork were successful.
 *                  Tracer::GENERIC_ERROR if the fork call failed.
 */
int Tracer::exec_program() {
	assert(!this->_running);
	assert(!this->_attached);
	assert(this->_program != nullptr);
	cout << "Going to execute: " << this->_program << endl;
	pid_t pid = fork();
	if (pid < 0) {
		PERROR("Fork error during " + string(this->_program) + " execution");
		return Tracer::GENERIC_ERROR;
	}
	if (pid == 0) {
		// Redirect child STDOUT to STDERR
		cout.rdbuf(cerr.rdbuf());
		if (ptrace(PTRACE_TRACEME)) {
			PERROR("Ptrace error while trying to set TRACEME in the child SPID " + to_string(this->_traced_spid));
			return Tracer::PTRACE_ERROR;
		}
		// The following will notify the parent that a sys_entry happened
		execvp(this->_program, const_cast<char**>(this->_args));
		PERROR("Impossible to execute the child process");
		// This does not call any functions registered with atexit or on_exit, open stdio streams are not flushed.
		_exit(-1);
	}
	this->_traced_pid = pid;
	this->_traced_spid = pid;
	this->_running = true;
	this->_attached = true;
	this->_condition_attach.notify_all();
	return 0;
}

/**
 * Attach through ptrace to the tracee.
 * If Tracer::_attach_callback is specified it will be called.
 * 
 * @return True if the PTRACE_ATTACH was successful, False otherwise.
 */
bool Tracer::attach() {
	assert(this->_traced_pid > 0 && this->_traced_pid < Tracer::MAX_PID);
	assert(this->_traced_spid > 0 && this->_traced_spid < Tracer::MAX_PID);
	assert(this->_running);
	if (ptrace(PTRACE_ATTACH, this->_traced_spid)) {
		PERROR("Ptrace error occurred while trying to ATTACH to thread SPID " + to_string(this->_traced_spid));
		return false;
	}
	this->_attached = true;
	this->_condition_attach.notify_all();
	if (this->_attach_callback != nullptr) {
		this->_attach_callback();
	}
	return true;
}

/**
 * Handle all the special cases that does not fit into the normal sysentry then sysexit ptrace behaviour.
 * 1 - When an exit_group or exit syscall is performed since PTRACE_O_TRACEEXIT was specified as ptrace option
 *     during the initialisation, we will be notified not only at the syscall exit but also a moment before 
 *     where the tracee registers are still available. 
 *     When an exit is detected the Tracer running status will be set to false.
 * 2 - If an execve syscall is performed there will be 3 notifications: sys_entry, sys_exit and sys_exec that
 *     informs us of the process image change.
 *     Furthermore it is necessary to inform TracingManager that an execve is going to be executed because it needs
 *     to remove every tracee that is not the thread group leader of this PID.
 * 3 - If a clone/fork/vfork syscall is performed there will be 3 notifications: sys_entry, sys_exec and sys_exit. 
 *     Only after the last one we know the return value thus if it succeed or not and the newly created task SPID.
 *     Furthermore it is necessary to inform TracingManager that the creation of a new Tracer is necessary.
 * In those special cases where 3 syscall notifications are expected this method skips one of them so the caller will
 * not notice the special behaviour.
 * 
 * @param status The status variable of the waitpid call that have received the sysentry notification.
 * @param regs The return value of a PTRACE_GETREGS performed by the caller, this can be changed in case of a skipped notification.
 * @return Returns: Tracer::NOT_SPECIAL     when no special actions are required.
 *                  Tracer::SYSCALL_HANDLED when the syscall has been already handled with some special measures.
 *                  Tracer::IMMINENT_EXIT   when the tracee is going to an end and the next notification will be a child death one.
 *                  Tracer::EXECVE_SYSCALL  if this tracee is going to perform a successfull execve
 *                  Tracer::PTRACE_ERROR    if a ptrace error occurred.
 *                  Tracer::EXITED_ERROR    if the tracee is going to an end in an unexpected manner.
 */
int Tracer::handle_special_cases(int status, shared_ptr<Registers> regs) {
	assert(this->_running);
	assert(this->_attached);
	assert(this->_traced_pid > 0 && this->_traced_pid < Tracer::MAX_PID);
	assert(this->_traced_spid > 0 && this->_traced_spid < Tracer::MAX_PID);
	int val, return_value;
	// If the tracee is going to die
	if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXIT << 8))) {
		if (ptrace(PTRACE_GETEVENTMSG, this->_traced_spid, nullptr, &val)) {
			PERROR("Ptrace error while trying to get the event message of this notification of SPID " + to_string(this->_traced_spid));
			return Tracer::PTRACE_ERROR;
		}
		cout << "The traced process " << this->_traced_spid << " is terminating with status: " << val << endl;
		this->_running = false;
		this->_attached = false;
		if (this->_current_state != nullptr) {
			cout << "The following system call will never be completed: " << endl;
			this->_current_state->print();
			this->_current_state = nullptr;
		}
		this->_termination_state = make_shared<ProcessTermination>(this->_traced_executable,
		                                                           this->_traced_pid,
		                                                           this->_traced_spid,
		                                                           val);
		return Tracer::IMMINENT_EXIT;
	}
	if (ptrace(PTRACE_GETREGS, this->_traced_spid, nullptr, regs.get())) {
		PERROR("Ptrace error occurred while trying to GETREGS from the process SPID " + to_string(this->_traced_spid));
		return Tracer::PTRACE_ERROR;
	}
	/* This option may not catch clone calls in all cases:
		 - If the tracee calls clone with the CLONE_VFORK flag -> PTRACE_EVENT_VFORK will be delivered instead.
		 - If the tracee calls clone with the exit signal set to SIGCHLD -> PTRACE_EVENT_FORK will be delivered. */
	if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
		assert(regs->nsyscall() == SYS_clone);
		assert(regs->ret_arg() == -ENOSYS);
		return_value = this->syscall_jump(regs);
		assert(this->_current_state->nsyscall == regs->nsyscall());
		this->_current_state->return_value = regs->ret_arg();
		if (return_value < 0) {
			return return_value;
		}
		this->_current_state->return_value = regs->ret_arg();
		if (this->_current_state->return_value < 1 || this->_current_state->return_value >= Tracer::MAX_PID) {
			return Tracer::NOT_SPECIAL;
		}
		// If the CLONE_THREAD option is specified means that the new thread will be in the same thread group of this tracee
		if ((this->_current_state->call_param.at(0) & CLONE_THREAD) && (this->_ptrace_options & PTRACE_O_TRACECLONE)) {
			this->_current_state->child_pid = this->_traced_pid;
			return_value = TracingManager::handle_children(*this, this->_traced_pid, (pid_t) this->_current_state->return_value);
		} else if (this->_ptrace_options & (PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK)) {
			this->_current_state->child_pid = (pid_t) this->_current_state->return_value;
			return_value = TracingManager::handle_children(*this,
			                                               (pid_t) this->_current_state->return_value,
			                                               (pid_t) this->_current_state->return_value);
		}
		if (!return_value) {
			return Tracer::SYSCALL_HANDLED;
		} else {
			return return_value;
		}
	}
	if ((status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK << 8))) || (status >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)))) {
		assert(regs->nsyscall() == SYS_fork || regs->nsyscall() == SYS_vfork || regs->nsyscall() == SYS_clone);
		assert(regs->ret_arg() == -ENOSYS);
		return_value = this->syscall_jump(regs);
		assert(this->_current_state->nsyscall == regs->nsyscall());
		this->_current_state->return_value = regs->ret_arg();
		if (return_value < 0) {
			return return_value;
		}
		this->_current_state->return_value = regs->ret_arg();
		if (this->_current_state->return_value < 1 || this->_current_state->return_value >= Tracer::MAX_PID) {
			return Tracer::NOT_SPECIAL;
		}
		this->_current_state->child_pid = (pid_t) this->_current_state->return_value;
		return_value = TracingManager::handle_children(*this,
		                                               (pid_t) this->_current_state->return_value,
		                                               (pid_t) this->_current_state->return_value);
		if (!return_value) {
			return Tracer::SYSCALL_HANDLED;
		} else {
			return return_value;
		}
	}
	if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
		if (!this->handle_execve(regs)) {
			this->_current_state->return_value = regs->ret_arg();
			return Tracer::EXECVE_SYSCALL;
		}
		return Tracer::PTRACE_ERROR;
	}
	return Tracer::NOT_SPECIAL;
}

/**
 * This is called when a syscall entry nofication is received by TracingManager::run method.
 * It performs some integrity checks and acquires all the parameters to construct a new ProcessState.
 * If the Program Counter base pointer has not been already defined it sets it with the address of the current
 * syscall instruction pointer value.
 * 
 * @param status The status variable of the waitpid call that have received the sysentry notification.
 * @return Returns: Tracer::WAIT_FOR_AUTHORISATION if the Tracee is still alive and will produce at least another notification.
 *                  Tracer::PTRACE_ERROR if a ptrace error occurred while trying to retrieve the tracee registers.
 */
int Tracer::systemcall_entry(int status, shared_ptr<Registers> regs) {
	assert(this->_running);
	assert(this->_attached);
	assert(this->_traced_pid > 0 && this->_traced_pid < Tracer::MAX_PID);
	assert(this->_traced_spid > 0 && this->_traced_spid < Tracer::MAX_PID);
	assert(this->_current_state == nullptr);
	assert(TracingManager::worker_spid == syscall(SYS_gettid));
	assert(WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80));
	assert(!WIFEXITED(status));
	this->_current_state = make_shared<ProcessSyscall>();
	if (ptrace(PTRACE_GETREGS, this->_traced_spid, nullptr, regs.get())) {
		PERROR("Ptrace error occurred while trying to GETREGS from the process SPID " + to_string(this->_traced_spid) + " during a syscall entry");
		return Tracer::PTRACE_ERROR;
	}
	//cout << "Sysentry PID: " << this->_traced_pid << " SPID: " << this->_traced_spid << " System call: " << regs->nsyscall() << endl;
	assert(regs->ret_arg() == -ENOSYS);                                           // The kernel sets rax to -ENOSYS in a syscall entry
	this->_current_state->tracer = TracingManager::tracers[this->_traced_spid];
	this->_current_state->_notification_origin = this->_traced_executable;
	this->_current_state->_pid = this->_traced_pid;
	this->_current_state->_spid = this->_traced_spid;
	if (!this->_pc_base_addr) {
		this->_pc_base_addr = regs->pc();
	}
	this->_current_state->relative_pc = (long long int) (regs->pc() - this->_pc_base_addr);
	this->_current_state->set_registers(regs);
	// Since after an execve authorisation will not be possible anymore to retrieve the target program we need
	// to extract it during the syscall entry and eventually overwrite it if this execve fails.
	if (this->_current_state->nsyscall == SYS_execve) {
		try {
			TracingManager::add_possible_execve(this->_traced_pid, this->extract_string(this->_current_state->call_param.at(0), PATH_MAX));
		} catch (runtime_error& e) {
			cerr << "Error while trying to retrieve the execve target program name: " << e.what() << endl;
		}
	}
	return Tracer::WAIT_FOR_AUTHORISATION;
}

/**
 * This assumes that the tracee is hanging at a syscall entry, thus it makes it proceed
 * and wait for its syscall exit notification in order to completely skip it.
 * This is called when a syscall gets authorised.
 * 
 * @param status The status variable of the waitpid call that have received the sysexit notification.
 * @return Returns: 0 when the syscall exit was successful.
 *                  Tracer::PTRACE_ERROR if a ptrace error occurred.
 */
int Tracer::systemcall_exit(int status, shared_ptr<Registers> regs) {
	assert(TracingManager::worker_spid == syscall(SYS_gettid));
	assert(this->_running);
	assert(this->_attached);
	assert(this->_traced_pid > 0 && this->_traced_pid < Tracer::MAX_PID);
	assert(this->_traced_spid > 0 && this->_traced_spid < Tracer::MAX_PID);
	assert(this->_current_state != nullptr);
	assert(this->_current_state->_spid > 0);
	assert(this->_current_state->regs_state != nullptr);
	assert(!this->_current_state->sp_backtrace.empty());
	assert(!this->_current_state->pc_backtrace.empty());
	assert(this->_no_backtrace || !this->_current_state->fn_backtrace.empty());
	assert(!this->_current_state->call_param.empty());
	assert(!WIFEXITED(status));
	this->_current_state->return_value = regs->ret_arg();
	if (this->_current_state->nsyscall != regs->nsyscall()) {
		cerr << "Received a different syscall number then expected in SPID " << this->_traced_spid << endl;
		cerr << "Received: " << regs->nsyscall() << endl;
		cerr << "Expected: " << this->_current_state->nsyscall << endl;
		if (regs->nsyscall() > MAX_SYSCALL_NUMBER || regs->nsyscall() < 0) {
			cerr << "The received value looks corrupted, maybe by a signal -> Ignore it" << endl;
		} else {
			cerr << "Unrecoverable state" << endl;
			return Tracer::PTRACE_ERROR;
		}
	}
	assert(this->_current_state->return_value != -ENOSYS);                        // In a real scenario this is possible but not in debug mode
	if (ptrace(PTRACE_SYSCALL, this->_traced_spid, nullptr, 0)) {
		PERROR("Ptrace error occurred while trying to continue from the syscall number " + to_string(this->_current_state->nsyscall) +
		       " exit notification of SPID " + to_string(this->_traced_spid));
		return Tracer::PTRACE_ERROR;
	}
	//cout << "System call number " << this->_current_state->nsyscall << " of SPID " << this->_traced_spid <<
	//     " return value: " << this->_current_state->return_value << endl;
	this->_current_state = nullptr;
	return 0;
}

/**
 * Used to skip a notification in some cases defined in Tracer::handle_special_cases: assumes that it is acting
 * in a special case where 3 notifications are received.
 * This method overrides the provided Registers parameter with the new syscall GETREGS value, furthermore
 * the syscall return value in Tracer::current_state is modified accordingly with the new registers status.
 * This assumes that the tracee is blocked in a syscall entry or exit so it will:
 * 1 - Unlock the tracee (PTRACE_SYSCALL).
 * 2 - Wait for the next syscall (waitpid).
 * It will NOT unlock the next syscall.
 * 
 * @param regs A reference to a Registers object.
 * @return Returns: 0 if 1 syscall notification was successfully jumped.
 *                  Tracer::PTRACE_ERROR if a ptrace error occurred.
 *                  Tracer::EXITED_ERROR if a tracee death notification has been received.
 */
int Tracer::syscall_jump(shared_ptr<Registers> regs) {
	assert(this->_running);
	assert(this->_attached);
	assert(this->_traced_pid > 0 && this->_traced_pid < Tracer::MAX_PID);
	assert(this->_traced_spid > 0 && this->_traced_spid < Tracer::MAX_PID);
	pid_t pid;
	int status;
	bool ptrace_signal = false;
	if (ptrace(PTRACE_SYSCALL, this->_traced_spid, nullptr, 0)) {
		PERROR("Ptrace error while trying to SYSCALL in order to jump a syscall of " + to_string(this->_traced_spid));
		return Tracer::PTRACE_ERROR;
	}
	do {
		pid = waitpid(this->_traced_spid, &status, __WALL);
		if (pid < 0) {
			PERROR("Waitpid error while waiting for child " + to_string(this->_traced_spid) + " during a syscall jump");
			return Tracer::GENERIC_ERROR;
		}
		assert(this->_traced_spid == pid);
		if (WIFEXITED(status)) {
			return Tracer::EXITED_ERROR;
		}
		if (WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80)) {
			ptrace_signal = true;
		} else if (this->handle_signal(status) == nullptr) {
			return Tracer::PTRACE_ERROR;
		}
	} while (!ptrace_signal);
	assert(this->_traced_spid == pid);
	assert(!WIFEXITED(status));
	if (ptrace(PTRACE_GETREGS, this->_traced_spid, nullptr, regs.get())) {
		PERROR("Ptrace error while trying to GETREGS after a syscall jump in SPID " + to_string(this->_traced_spid));
		return Tracer::PTRACE_ERROR;
	}
	cout << "Jumped syscall number: " << regs->nsyscall() << " Return value: " << regs->ret_arg() << " SPID: " << this->_traced_spid << endl;
	return 0;
}

/**
 * Handle the case of an execve system call in this thread.
 * This is a delicate case since when it gets executed every thread that is not the thread group
 * leader, such that PID == SPID, is immediately stopped and destroyed by the kernel.
 * If another thread execute an execve it will still appear that the thread group leader has executed it.
 * The executable change thanks to the TracingManager.
 * 
 * @param regs The return value of a PTRACE_GETREGS performed by the caller, this can be changed in case of a skipped notification.
 * @return Returns: 0 if the execve handling was successful.
 *                  Tracer::PTRACE_ERROR if there was an error during the new executable name retrival.
 */
int Tracer::handle_execve(shared_ptr<Registers> regs) {
	assert(this->_running);
	assert(this->_attached);
	assert(this->_traced_pid > 0 && this->_traced_pid < Tracer::MAX_PID);
	assert(this->_traced_spid > 0 && this->_traced_spid < Tracer::MAX_PID);
	assert(this->_traced_pid == this->_traced_spid);
	cout << "New tracee executable name: " << TracingManager::possible_execves[this->_traced_pid] << endl;
	// When a process calls execve, ASLR relocates the position of stack and libraries
	this->_sp_base_addr = 0;
	this->_pc_base_addr = 0;
	return this->syscall_jump(regs) >= 0 ? 0 : Tracer::PTRACE_ERROR;
}

/**
 * Extracts a NULL terminated string from the tracee address space.
 * 
 * @param address    String starting point address in the tracee memory.
 * @param max_length The maximum number of byte to retrieve from tracee memory before stopping the extraction.
 * @return The string starting from address and terminating in the first NULL byte
 */
string Tracer::extract_string(unsigned long long int address, unsigned int max_length) const {
	assert(this->_running);
	assert(this->_attached);
	assert(this->_traced_pid > 0 && this->_traced_pid < Tracer::MAX_PID);
	assert(this->_traced_spid > 0 && this->_traced_spid < Tracer::MAX_PID);
	union name_chunk_t {
		long value;
		char chars[sizeof(long)];
	} name_chunk;
	string result;
	unsigned int i = 0;
	errno = 0;
	do {
		name_chunk.value = ptrace(PTRACE_PEEKDATA, this->_traced_spid, address + i, nullptr);
		if (errno) {
			PERROR("Error during the new executabe name retrieval from SPID " + to_string(this->_traced_spid));
			throw new runtime_error("Impossible to retrieve data from tracee memory");
		}
		result += string(name_chunk.chars);
		i += 4;
	} while (find(begin(name_chunk.chars), end(name_chunk.chars), NULL) == end(name_chunk.chars) && i < max_length);
	return result;
}

/**
 * This handles a signal that does not come from ptrace and will be directly delivered
 * to the Tracee.
 * This method does NOT let the tracee proceed to the next syscall.
 * 
 * @param status The status generated by the waitpid call.
 * @return A pointer to a siginfo_t structure that contains the signal details. nullptr if an error occurs.
 */
shared_ptr<siginfo_t> Tracer::handle_signal(int status) const {
	assert(this->_running);
	assert(this->_attached);
	assert(this->_traced_pid > 0 && this->_traced_pid < Tracer::MAX_PID);
	assert(this->_traced_spid > 0 && this->_traced_spid < Tracer::MAX_PID);
	assert(!WIFEXITED(status));
	assert(!WIFSTOPPED(status) || WSTOPSIG(status) != (SIGTRAP | 0x80));
	shared_ptr<siginfo_t> signal_info = make_shared<siginfo_t>();
	if (ptrace(PTRACE_GETSIGINFO, this->_traced_spid, nullptr, signal_info.get())) {
		PERROR("Ptrace error occurred while trying to retrieve the signal info of " + to_string(this->_traced_spid));
		return nullptr;
	}
	cout << "Signal directed to SPID " << this->_traced_spid << " has been intercepted" << endl;
	cout << "Signal number: " << signal_info->si_signo << endl;
	cout << "Signal description: " << string(strsignal(signal_info->si_signo)) << endl;
	if (signal_info->si_errno) {
		cout << "Signal error number" << signal_info->si_errno << endl;
	}
	cout << "Signal code: " << signal_info->si_code << endl;
	if (signal_info->si_code == SI_USER ||
	    signal_info->si_code == SI_QUEUE ||
	    signal_info->si_code == SI_TIMER ||
	    signal_info->si_code == SI_ASYNCIO ||
	    signal_info->si_code == SI_MESGQ ||
	    signal_info->si_signo == SIGCHLD) {
		cout << "Sending PID: " << signal_info->si_pid << endl;
		cout << "Sending Real UID: " << signal_info->si_uid << endl;
		if (signal_info->si_code != SI_USER && signal_info->si_signo != SIGCHLD) {
			cout << "Signal value: " << signal_info->si_value.sival_int << " pointer: " << signal_info->si_value.sival_ptr << endl;
		}
		if (signal_info->si_signo == SIGCHLD) {
			cout << "Child exit value or signal: " << signal_info->si_status << endl;
		}
	}
	if (signal_info->si_signo == SIGILL || signal_info->si_signo == SIGFPE) {
		cout << "Address of failing instruction: " << signal_info->si_addr << endl;
	}
	if (signal_info->si_signo == SIGSEGV || signal_info->si_signo == SIGBUS) {
		cout << "Faulting memory reference: " << signal_info->si_addr << endl;
	}
	if (signal_info->si_signo == SIGIO || signal_info->si_signo == SIGPOLL) {
		cout << "Band event: " << signal_info->si_band << endl;
	}
	if (signal_info->si_signo == SIGPOLL) {
		cout << "I/O event file descriptor: " << signal_info->si_fd << endl;
	}
	if (signal_info->si_signo == SIGSYS) {
		cout << "Calling user instruction: " << signal_info->si_call_addr << endl;
		cout << "Triggering system call number: " << signal_info->si_syscall << endl;
		cout << "CPU architecture of the syscall: " << signal_info->si_arch << endl;
	}
	if (signal_info->si_signo == SIGALRM || signal_info->si_signo == SIGPROF) {
		cout << "Timer ID: " << signal_info->si_timerid << endl;
		cout << "Overrun count: " << signal_info->si_overrun << endl;
		cout << "Signal value: " << signal_info->si_value.sival_int << " pointer: " << signal_info->si_value.sival_ptr << endl;
	}
	if (ptrace(PTRACE_SETSIGINFO, this->_traced_spid, nullptr, signal_info.get())) {
		PERROR("Ptrace error occurred while trying to set the signal info of " + to_string(this->_traced_spid));
		return nullptr;
	}
	if (ptrace(PTRACE_SYSCALL, this->_traced_spid, nullptr, signal_info->si_signo)) {
		PERROR("Ptrace error occurred while trying to restart the SPID " + to_string(this->_traced_spid) + " after a signal reception");
		return nullptr;
	}
	return signal_info;
}