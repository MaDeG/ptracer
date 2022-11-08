#include <boost/format.hpp>
#include "StackFrame.h"

using namespace std;

StackFrame::StackFrame(unsigned long long int pc,
						           unsigned long long int relativePc,
						           unsigned long long int sp,
						           string functionName,
						           unsigned long long int functionOffset) : pc(pc),
                                                                relativePc(relativePc),
                                                                sp(sp),
                                                                functionName(functionName),
                                                                functionOffset(functionOffset){
}

StackFrame::operator std::string() const {
	string result;
	result = (boost::format("PC %#016x Relative PC %#016x SP %016x - %s x%d") % this->pc % this->relativePc % this->sp % this->functionName % this->functionOffset).str();
	//printf("PC %#016x Relative PC %#016x SP %016x - %s x%d", this->pc, this->relative_pc, this->sp, this->function_name, this->function_offset);
	return result;
}