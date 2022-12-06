#ifndef PTRACER_STACKFRAMEDTO_H
#define PTRACER_STACKFRAMEDTO_H

#include "../StackFrame.h"

class StackFrameDTO {
public:
	StackFrameDTO(std::string flat);
	StackFrameDTO(const StackFrame& frame);
	[[nodiscard]] std::string serialize() const;
	bool operator==(const StackFrameDTO& that) const;
	bool operator!=(const StackFrameDTO& that) const;
	bool operator<(const StackFrameDTO& that) const;
private:
	static const std::string SEPARATOR;
	std::string functionName;
	unsigned int offset;
};

#endif //PTRACER_STACKFRAMEDTO_H
