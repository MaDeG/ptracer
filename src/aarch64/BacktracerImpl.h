#ifndef PTRACER_BACKTRACERIMPL_H
#define PTRACER_BACKTRACERIMPL_H
#include <unwindstack/Unwinder.h>
#include "../Backtracer.h"
#include "../StackFrame.h"

class BacktracerImpl : public Backtracer {
public:
	BacktracerImpl() : Backtracer() { }
	void init(pid_t pid) override;
	std::vector<StackFrame> unwind() override;
	~BacktracerImpl() override = default;

private:
	static const unsigned int MAX_FRAMES;
	pid_t pid;
	std::unique_ptr<unwindstack::UnwinderFromPid> unwinder;
};

#endif //PTRACER_BACKTRACERIMPL_H
