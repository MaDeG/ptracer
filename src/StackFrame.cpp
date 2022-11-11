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
	string result = (boost::format("PC %#016x Relative PC %#016x SP %016x") % this->pc % this->relativePc % this->sp).str();
	if (!this->functionName.empty()) {
		result += (boost::format(" - %s @ %d") % this->functionName % this->functionOffset).str();
	}
	return result;
}