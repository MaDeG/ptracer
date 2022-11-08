#ifndef PTRACER_BACKTRACER_H
#define PTRACER_BACKTRACER_H
#include <memory>
#include <vector>
#include "StackFrame.h"

class Backtracer {
public:
	virtual void init(pid_t pid) = 0;
	virtual std::vector<StackFrame> unwind() = 0;
	virtual ~Backtracer() = default;
	Backtracer(const Backtracer& other) = delete;
	Backtracer& operator = (const Backtracer& other) = delete;
	static std::unique_ptr<Backtracer> getInstance();

protected:
	Backtracer() { }
};

#endif //PTRACER_BACKTRACER_H