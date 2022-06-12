#include <boost/program_options.hpp>
#include <iostream>
#include "Launcher.h"
#include "TracingManager.h"

using namespace std;
using namespace boost::program_options;

const string Launcher::PROGRAM_NAME = "Ptracer";
const string Launcher::PROGRAM_DESC = "Trace syscalls via ptrace";
const string Launcher::HELP_OPT = "help";
const string Launcher::PID_OPT = "pid";
const string Launcher::RUN_OPT = "run";
const string Launcher::FOLLOW_THREADS_OPT = "follow-threads";
const string Launcher::FOLLOW_CHILDREN_OPT = "follow-children";
const string Launcher::JAIL_OPT = "jail";

/**
 * The two main parameters are necessary since we need to get the initialisation parameters.
 *
 * @param argc          The arguments counter passed to the main function.
 * @param argv          The nullptr terminated string array passed to the main function.
 * @throw runtime_error In case of an error in the command line parameters parsing.
 */
Launcher::Launcher(int argc, const char** argv) {
	boost::program_options::options_description description("Ptracer usage");
	description.add_options()(Launcher::HELP_OPT.c_str(), "Display this help message")
			(Launcher::PID_OPT.c_str(), value<long>(), "PID of the process to trace")
			(Launcher::RUN_OPT.c_str(), value<string>(), "Run and Trace the specified program with parameters, if specified needs to be the last option")
			(Launcher::FOLLOW_THREADS_OPT.c_str(), value<bool>()->default_value(true), "Trace also child threads")
			(Launcher::FOLLOW_CHILDREN_OPT.c_str(), value<bool>()->default_value(true), "Trace also child processes")
			(Launcher::JAIL_OPT.c_str(), value<bool>()->default_value(false), "Kill the traced process and all its children if ptracer is killed");
	parsed_options parsed = command_line_parser(argc, argv).options(description)
			.allow_unregistered()
			.run();
	boost::program_options::variables_map option_values;
	store(parsed, option_values);
	notify(option_values);
	if (option_values.count(Launcher::HELP_OPT)) {
		cout << Launcher::PROGRAM_NAME << " - " << Launcher::PROGRAM_DESC << endl;
		cout << description << endl;
	}
	if (option_values.count(Launcher::PID_OPT)) {
		this->traced_pid = option_values[Launcher::PID_OPT].as<pid_t>();
	} else if (option_values.count(Launcher::RUN_OPT)) {
		for (int i = 1; i < argc; i++) {
			if (!strcmp(argv[i], ("--" + Launcher::RUN_OPT).c_str())) {
				this->tracee_argv = (char**) &argv[i + 1];
				break;
			}
		}
	} else {
		throw new runtime_error("Either a PID or a command to run must be specified!");
	}
	this->follow_threads = option_values[Launcher::FOLLOW_THREADS_OPT].as<bool>();
	this->follow_children = option_values[Launcher::FOLLOW_CHILDREN_OPT].as<bool>();
	this->tracee_jail = option_values[Launcher::JAIL_OPT].as<bool>();
}

void Launcher::start() {
	if (this->tracee_argv != nullptr) {
		cout << "Executable to trace: " << this->tracee_argv[0] << endl;
		cout << "Parameters to pass:" << endl;
		int i = 1;
		while (this->tracee_argv[i] != nullptr) {
			cout << "[" << i << "] -> " << this->tracee_argv[i] << endl;
			i++;
		}
	} else {
		cout << "PID to trace: " << this->traced_pid << endl;
	}
	cout << "Follow threads: " << (this->follow_threads ? "true" : "false") << endl;
	cout << "Follow children: " << (this->follow_children ? "true" : "false") << endl;
	cout << "Tracee jail: " << (this->tracee_jail ? "true" : "false") << endl;

	TracingManager::init(make_shared<Tracer>(const_cast<char*> (this->tracee_argv[0]),
	                                                const_cast<char const* const*> (this->tracee_argv),
	                                                this->follow_children,
	                                                this->follow_threads,
	                                                this->tracee_jail,
	                                                true));
	TracingManager::start();
	this->print_syscalls();
}

void Launcher::print_syscalls() const {
	shared_ptr<ProcessNotification> notification;
	while ((notification = TracingManager::next_notification()) != nullptr) {
		
		shared_ptr<ProcessSyscall> syscall = dynamic_pointer_cast<ProcessSyscall>(notification);
		if (notification != nullptr) {
			TracingManager::authorise(dynamic_pointer_cast<ProcessSyscall>(notification));
			cout << syscall->get_timestamp() << " - ";
			cout << "PID: " << syscall->get_pid() << " - ";
			cout << "SPID: " << syscall->get_spid() << " - ";
			cout << "Syscall: " << syscall->get_nsyscall() << endl;
		}
	}
}