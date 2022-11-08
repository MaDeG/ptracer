#ifndef PTRACER_STACKFRAME_H
#define PTRACER_STACKFRAME_H
#include <string>

struct StackFrame {
	const unsigned long long int pc;
	const unsigned long long int relativePc;
	const unsigned long long int sp;
	const std::string functionName;
	const unsigned long long int functionOffset;
	StackFrame(unsigned long long int pc,
	           unsigned long long int relativePc,
	           unsigned long long int sp,
	           std::string functionName,
	           unsigned long long int functionOffset);
	operator std::string() const;
};

#endif //PTRACER_STACKFRAME_H
