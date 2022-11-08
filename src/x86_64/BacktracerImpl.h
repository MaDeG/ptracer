#ifndef PTRACER_BACKTRACERIMPL_H
#define PTRACER_BACKTRACERIMPL_H
#include <libunwind-ptrace.h>
#include "../Backtracer.h"
#include "../StackFrame.h"

class BacktracerImpl : public Backtracer {
public:
	BacktracerImpl();
	void init(pid_t pid) override;
	std::vector<StackFrame> unwind() override;
	~BacktracerImpl() override;

private:
	static const unsigned int MAX_FRAMES;
	static const unsigned int MAX_FUNCTION_NAME_LENGTH;
	unw_addr_space_t _address_space = nullptr;
	struct UPT_info* _info = nullptr;
};

#endif //PTRACER_BACKTRACERIMPL_H
