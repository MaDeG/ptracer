#include "Authorizer.h"

#ifndef PTRACER_LAUNCHER_H
#define PTRACER_LAUNCHER_H

class Launcher {
public:
	Launcher(int argc, const char** argv);
	void start();

private:
	static const std::string PROGRAM_NAME;
	static const std::string PROGRAM_DESC;
	static const std::string HELP_OPT;
	static const std::string PID_OPT;
	static const std::string RUN_OPT;
	static const std::string FOLLOW_THREADS_OPT;
	static const std::string FOLLOW_CHILDREN_OPT;
	static const std::string JAIL_OPT;
	static const std::string BACKTRACE_OPT;
	static const std::string AUTHORIZER_OPT;
	static const std::string LEARN_OPT;
	static const std::string NFA_PATH_OPT;
	static const std::string DOT_PATH_OPT;
	static const std::string ASSOCIATIONS_PATH_OPT;
	pid_t traced_pid = -1;
	char** tracee_argv = nullptr;
	bool follow_threads;
	bool follow_children;
	bool tracee_jail;
	bool backtrace;
	std::unique_ptr<Authorizer> authorizer;
	std::string dotPath;
	void processSyscalls() const;
};


#endif //PTRACER_LAUNCHER_H
