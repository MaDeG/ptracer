#ifndef PTRACER_LAUNCHER_H
#define PTRACER_LAUNCHER_H

class Launcher {
private:
	static const std::string PROGRAM_NAME;
	static const std::string PROGRAM_DESC;
	static const std::string HELP_OPT;
	static const std::string PID_OPT;
	static const std::string RUN_OPT;
	static const std::string FOLLOW_THREADS_OPT;
	static const std::string FOLLOW_CHILDREN_OPT;
	static const std::string JAIL_OPT;
	pid_t traced_pid = -1;
	char** tracee_argv = nullptr;
	bool follow_threads;
	bool follow_children;
	bool tracee_jail;
	void print_syscalls() const;

public:
	Launcher(int argc, const char** argv);
	void start();
};


#endif //PTRACER_LAUNCHER_H
