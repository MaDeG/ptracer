#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <vector>
#include "StackFrameDto.h"

using namespace std;

const string StackFrameDTO::SEPARATOR = "@";

StackFrameDTO::StackFrameDTO(string flat) {
	vector<string> tokens;
	boost::split(tokens, flat, boost::is_any_of(StackFrameDTO::SEPARATOR));
	if (tokens.size() != 2) {
		throw new runtime_error("Error in StackFrame deserialization: incorrect format");
	}
	this->functionName = tokens.at(0);
	this->offset = boost::lexical_cast<int>(tokens.at(1));
}

StackFrameDTO::StackFrameDTO(const StackFrame& frame) {
	this->functionName = frame.functionName;
	this->offset = frame.functionOffset;
}

string StackFrameDTO::serialize() const {
	return this->functionName + StackFrameDTO::SEPARATOR + to_string(this->offset);
}

/**
 * It provides the possibility to do an equality check between two StackFramesDTO.
 * This is used when comparing two ProcessSyscallEntryDTO.
 *
 * @param that The FunctionOffset to check with.
 * @return True if this and fr1 are equals, False otherwise.
 */
bool StackFrameDTO::operator==(const StackFrameDTO& that) const {
	return this->functionName == that.functionName && this->offset == that.offset;
}

/**
 * It provides the possibility to check if two StackFramesDTOs are different.
 * It is simply the negated version of the equality check.
 *
 * @param that The StackFramesDTO to check with.
 * @return True if this and that are different, False otherwise.
 */
bool StackFrameDTO::operator!=(const StackFrameDTO& that) const {
	return !(*this == that);
}

/**
 * It provides the possibility to compare two StackFramesDTOs.
 * This is used when the bimap will sort ProcessSyscallEntryDTOs comparing them.
 *
 * @param that The StackFramesDTOs that will be compared with this.
 * @return True if this < that, False otherwise.
 */
bool StackFrameDTO::operator<(const StackFrameDTO& that) const {
	if (this->functionName != that.functionName) {
		return this->functionName.compare(that.functionName) < 0;
	}
	return this->offset < that.offset;
}