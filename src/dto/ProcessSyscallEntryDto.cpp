#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include "ProcessSyscallEntryDto.h"

using namespace std;

// TODO: Use YAML to store this data

// Delimiter that will be used to separate fields in the serialized representation
const string ProcessSyscallEntryDTO::FIELD_SEPARATOR = "\x1E";
// Separator that will be used to separate values inside a filed in the serialized representation
const string ProcessSyscallEntryDTO::VALUE_SEPARATOR = "\x1F";
// Line delimiter that will be used to indicate the end of a serialized object
const string ProcessSyscallEntryDTO::END_OF_OBJECT = "\n";

ProcessSyscallEntryDTO::ProcessSyscallEntryDTO(const ProcessSyscallEntry& syscall){
	this->executableName = syscall.getExecutableName();
	this->syscall = syscall.getSyscall();
	for (const StackFrame& i : syscall.getStackFrames()) {
		this->frames.emplace_back(i);
	}
}

/**
 * Given a serialised representation of a ProcessSyscallEntryDTO object this is able to deserialize it.
 * Only System call number and Backtrack function names with relative offset will be restored.
 *
 * @param flat The string representation of a serialised ProcessSyscallEntry.
 */
ProcessSyscallEntryDTO::ProcessSyscallEntryDTO(const string flat, const string& executableName) {
	vector<string> tokens;
	boost::split(tokens, flat, boost::is_any_of(ProcessSyscallEntryDTO::FIELD_SEPARATOR));
	if (tokens.size() != 1 && tokens.size() != 2) {
		throw new runtime_error("Error in ProcessSyscallEntry deserialization: incorrect format");
	}
	this->syscall = boost::lexical_cast<int>(tokens.at(0));
	if (this->syscall < 0) {
		throw new runtime_error("Error in ProcessSyscall deserialization: found invalid syscall number: " + tokens.at(0));
	}
	if (tokens.size() == 2) {
		string backtrace_data = tokens.at(1);
		tokens.clear();
		boost::split(tokens, backtrace_data, boost::is_any_of(ProcessSyscallEntryDTO::VALUE_SEPARATOR));
		for (string& entry : tokens) {
			this->frames.emplace_back(entry);
		}
	}
	this->executableName = executableName;
}

/**
 * Generates a serialised version of this ProcessSyscallEntry object with the most important
 * information that can identify a syscall:
 * System call number, Backtrack function names with relative offset.
 * One of the constructors is able to do the inverse operation.
 *
 * @return The serialised object in string format.
 */
string ProcessSyscallEntryDTO::serialize() const {
	// TODO: Maybe there is a faster way to concatenate strings
	string flat;
	flat += to_string(this->syscall) + ProcessSyscallEntryDTO::FIELD_SEPARATOR;
	for (const StackFrameDTO& i : this->frames) {
		flat += i.serialize() + ProcessSyscallEntryDTO::VALUE_SEPARATOR;
	}
	flat.resize(flat.size() - ProcessSyscallEntryDTO::VALUE_SEPARATOR.size());
	flat += END_OF_OBJECT;
	return flat;
}

/**
 * Define the equality check that Bimap will use to find a ProcessSyscallEntryDTO
 *
 * @param that The ProcessState that will be checked for equality.
 * @return True if this == compare, False otherwise.
 */
bool ProcessSyscallEntryDTO::operator==(const ProcessSyscallEntryDTO& that) const {
	if (this->syscall != that.syscall) {
		return false;
	}
	if (this->frames != that.frames) {
		return false;
	}
	return true;
}

/**
 * Define the inequality check between two ProcessSyscallEntryDTOs as the inverse of the equity check.
 *
 * @param compare The ProcessSyscallEntryDTO that will be checked for inequality.
 * @return True if this != compare, False otherwise.
 */
bool ProcessSyscallEntryDTO::operator!=(const ProcessSyscallEntryDTO& that) const {
	return !(*this == that);
}

/**
 * Define the comparison mechanism that the Bimap will use to sort ProcessStates.
 *
 * @param that The ProcessState that will be compared with this
 * @return True if this < compare, False otherwise
 */
bool ProcessSyscallEntryDTO::operator<(const ProcessSyscallEntryDTO& that) const {
	if (this->syscall != that.syscall) {
		return this->syscall < that.syscall;
	}
	vector<StackFrameDTO>::const_iterator itThis, itThat;
	for (itThis = this->frames.begin(), itThat = that.frames.begin();
			 itThis != this->frames.end() && itThat != that.frames.end();
			 itThis++, itThat++) {
		if (*itThis != *itThat) {
			return *itThis < *itThat;
		}
	}
	// Consider the longest stack trace as lower
	return this->frames.size() > that.frames.size();
}