#include <boost/program_options.hpp>
#include <iostream>
#include "Launcher.h"
#include "TracingManager.h"
#include "SyscallDecoderMapper.h"

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
const string Launcher::BACKTRACE_OPT = "backtrace";
const string Launcher::AUTHORIZER_OPT = "authorizer";
const string Launcher::LEARN_OPT = "learn";
const string Launcher::NFA_PATH_OPT = "nfa";
const string Launcher::DOT_PATH_OPT = "dot";
const string Launcher::ASSOCIATIONS_PATH_OPT = "associations";

void terminationHandler(int signum) {
	cout << "Termination signal received" << endl;
	SyscallDecoderMapper::printReport();
	exit(1);
}

/**
 * The two main parameters are necessary since we need to get the initialisation parameters.
 *
 * @param argc          The arguments counter passed to the main function.
 * @param argv          The nullptr terminated string array passed to the main function.
 * @throw runtime_error In case of an error in the command line parameters parsing.
 */
Launcher::Launcher(int argc, const char** argv) {
	boost::program_options::options_description description("Ptracer usage");
	description.add_options()
			(Launcher::HELP_OPT.c_str(), "Display this help message")
			(Launcher::PID_OPT.c_str(), value<long>(), "PID of the process to trace")
			(Launcher::RUN_OPT.c_str(), value<string>(), "Run and Trace the specified program with parameters, if specified needs to be the last option")
			(Launcher::FOLLOW_THREADS_OPT.c_str(), value<bool>()->default_value(true), "Trace also child threads")
			(Launcher::FOLLOW_CHILDREN_OPT.c_str(), value<bool>()->default_value(true), "Trace also child processes")
			(Launcher::JAIL_OPT.c_str(), value<bool>()->default_value(false), "Kill the traced process and all its children if ptracer is killed")
			(Launcher::BACKTRACE_OPT.c_str(), value<bool>()->default_value(true), "Extract the full stacktrace that lead to a systemcall")
			(Launcher::AUTHORIZER_OPT.c_str(), value<bool>()->default_value(false), "Enable or disables the Authorizer module and all its options")
			(Launcher::LEARN_OPT.c_str(), value<bool>()->default_value(true), "Sets the Authorizer module in learning mode")
			(Launcher::NFA_PATH_OPT.c_str(), value<string>(), "Specifies the path where the NFA managed by the Auhtorizer is present or will be created")
			(Launcher::DOT_PATH_OPT.c_str(), value<string>(), "Specifies the path where the DOT representation of the NFA managed by the Auhtorizer will be created")
			(Launcher::ASSOCIATIONS_PATH_OPT.c_str(), value<string>(), "Specifies the path where the associations between state IDs and System Calls is present or will be created by the Authorizer")
	;
	parsed_options parsed = command_line_parser(argc, argv).options(description)
																												 .allow_unregistered()
																												 .run();
	boost::program_options::variables_map option_values;
	try {
		store(parsed, option_values);
		notify(option_values);
	} catch (boost::program_options::error& e) {
		throw runtime_error(string(e.what()));
	}
	if (option_values.count(Launcher::HELP_OPT) > 0) {
		cout << Launcher::PROGRAM_NAME << " - " << Launcher::PROGRAM_DESC << endl;
		cout << description << endl;
		return;
	}
	if (option_values.count(Launcher::PID_OPT) > 0) {
		this->traced_pid = option_values[Launcher::PID_OPT].as<long>();
	} else if (option_values.count(Launcher::RUN_OPT) > 0) {
		for (int i = 1; i < argc; i++) {
			if (!strcmp(argv[i], ("--" + Launcher::RUN_OPT).c_str())) {
				this->tracee_argv = (char**) &argv[i + 1];
				break;
			}
		}
	}
	else {
		throw runtime_error("Either a PID or a command to run must be specified! Use the --help option to see a list of available parameters");
	}
	this->follow_threads = option_values[Launcher::FOLLOW_THREADS_OPT].as<bool>();
	this->follow_children = option_values[Launcher::FOLLOW_CHILDREN_OPT].as<bool>();
	this->tracee_jail = option_values[Launcher::JAIL_OPT].as<bool>();
	this->backtrace = option_values[Launcher::BACKTRACE_OPT].as<bool>();
	if (option_values[Launcher::AUTHORIZER_OPT].as<bool>()) {
		if (option_values.count(Launcher::NFA_PATH_OPT) <= 0 || option_values.count(Launcher::ASSOCIATIONS_PATH_OPT) <= 0) {
			throw runtime_error("The Authorizer module requires to specify a path where the NFA is saved and retrieved (if exists) and a path where to store the IDs <-> syscalls associations");
		}
		this->authorizer = make_unique<Authorizer>(option_values[Launcher::NFA_PATH_OPT].as<string>(),
		                                           option_values[Launcher::ASSOCIATIONS_PATH_OPT].as<string>(),
		                                           option_values[Launcher::LEARN_OPT].as<bool>());
		this->dotPath = option_values[Launcher::DOT_PATH_OPT].as<string>();
	}
}

void Launcher::start() {
	if (this->tracee_argv == nullptr && this->traced_pid < 0) {
		cerr << "Either a PID or a command to run must be specified! Use the -h option for help." << endl;
		return;
	}
	cout << "Follow threads: " << (this->follow_threads ? "true" : "false") << endl;
	cout << "Follow children: " << (this->follow_children ? "true" : "false") << endl;
	cout << "Tracee jail: " << (this->tracee_jail ? "true" : "false") << endl;
	cout << "Authorizer module is " << (this->authorizer ? "active" : "NOT active") << endl;
	if (this->authorizer) {
		cout << string(*this->authorizer);
		cout << "DOT Output: " << this->dotPath << endl;
	}
	if (this->tracee_argv != nullptr) {
		cout << "Executable to trace: " << this->tracee_argv[0] << endl;
		cout << "Parameters to pass:" << endl;
		int i = 1;
		while (this->tracee_argv[i] != nullptr) {
			cout << "[" << i << "] -> " << this->tracee_argv[i] << endl;
			i++;
		}
		TracingManager::init(make_shared<Tracer>(const_cast<char*> (this->tracee_argv[0]),
																						 const_cast<char const* const*> (this->tracee_argv),
		                                         this->follow_children,
																						 this->follow_threads,
																						 this->tracee_jail,
																						 this->backtrace));
	} else {
		cout << "PID to trace: " << this->traced_pid << endl;
		TracingManager::init(make_shared<Tracer>("attached-process-" + to_string(this->traced_pid),
																			       this->traced_pid,
																						 this->follow_children,
																						 this->follow_threads,
																						 this->tracee_jail,
																						 this->backtrace));
	}
	signal(SIGINT, terminationHandler);
	TracingManager::start();
	this->processSyscalls();
}

void Launcher::processSyscalls() const {
	shared_ptr<ProcessNotification> notification;
	while ((notification = TracingManager::nextNotification()) != nullptr) {
		// TODO: There should be no need to cast down
		// TODO: Find a better way to register syscalls to the Authorizer module as well as the Decoders
		shared_ptr<ProcessSyscallEntry> syscall = dynamic_pointer_cast<ProcessSyscallEntry>(notification);
		notification->print();
		if (this->authorizer) {
			this->authorizer->process(notification);
		} else if (syscall) {
			shared_ptr<ProcessSyscallEntry> entry = dynamic_pointer_cast<ProcessSyscallEntry>(notification);
			TracingManager::authorize(entry);
		}
	}
	if (this->authorizer) {
		this->authorizer->terminate();
		if (!this->dotPath.empty()) {
			this->authorizer->dotOutput(this->dotPath);
		}
	}
	SyscallDecoderMapper::printReport();
}
