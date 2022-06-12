#include <stdexcept>
#include <vector>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>
#include "FunctionOffset.h"

using namespace std;

// Delimiter used to separate a function name and the offset specification
const string FunctionOffset::OFFSET_DELIMITER = "@";

/**
 * It constructs a new FunctionOffset starting from a function name and an offset.
 * 
 * @param function_name The function name of this entry.
 * @param offset The offset of this function call.
 */
FunctionOffset::FunctionOffset(const string function_name, const unsigned long long int offset) {
  this->_function_name = function_name;
  this->_offset = offset;
  this->_valid = true;
}

/**
 * It constructs a new FunctionOffset starting from a stack pointer and an offset.
 * This is used in case the function name is not available
 * 
 * @param stack_pointer The Stack Pointer of this stack entry.
 * @param offset The offset of this function call.
 */
FunctionOffset::FunctionOffset(const long long int stack_pointer, const unsigned long long int offset) {
  this->_stack_pointer = stack_pointer;
  this->_offset = offset;
  this->_valid = true;
}

/**
 * It is able to deserialize a flat version of a FunctionOffset.
 * It expects a string with the following format: (function_name)(FunctionOffset::OFFSET_DELIMITER)(offset),
 * the offset must be a unsigned integer.
 * 
 * @param serialized A well formed serialized FunctionOffset.
 * @throws runtime_error In case of a malformed serialized FunctionOffset.
 */
FunctionOffset::FunctionOffset(const string serialized) {
  vector<string> tokens;
  boost::split(tokens, serialized, boost::is_any_of(FunctionOffset::OFFSET_DELIMITER));
  if (tokens.size() != 2) {
    throw new runtime_error("Invalid function name and offset found: " + serialized);
  }
  try {
    this->_stack_pointer = boost::lexical_cast<long long int>(tokens.at(0));
  } catch (boost::bad_lexical_cast& e) {
    this->_function_name = tokens.at(0);
  }
  this->_offset = boost::lexical_cast<unsigned long long int>(tokens.at(1));
  this->_valid = true;
}

/**
 * In case of an initialisation error a FunctionOffset may contain corrupted data.
 * 
 * @return True if the content is valid, False otherwise.
 */
bool FunctionOffset::is_valid() const {
  return this->_valid;
}

/**
 * It provides the possibility to cast a FunctionOffset in its string representation that
 * is also its serialized format.
 * 
 * @return The string representation (or serialized version) of this object when casted to string.
 */
FunctionOffset::operator string() const {
  if (!this->_function_name.empty()) {
    return this->_function_name + FunctionOffset::OFFSET_DELIMITER + to_string(this->_offset);
  }
  return to_string(this->_stack_pointer) + FunctionOffset::OFFSET_DELIMITER + to_string(this->_offset);
}

/**
 * It provides the possibility to do an equality check between two FunctionOffsets.
 * This is used when comparing two ProcessStates.
 * 
 * @param compare The FunctionOffset to check with.
 * @return True if this and fr1 are equals, False otherwise.
 */
bool FunctionOffset::operator==(const FunctionOffset &compare) const {
  if (!this->_function_name.empty()) {
    return this->_function_name == compare._function_name && this->_offset == compare._offset;
  } else {
    return this->_stack_pointer == compare._stack_pointer && this->_offset == compare._offset;
  }
}

/**
 * It provides the possibility to check if two FunctionOffsets are different.
 * It is simply the negated version of the equality check.
 * 
 * @param compare The FunctionOffset to check with.
 * @return True if this and fr1 are different, False otherwise.
 */
bool FunctionOffset::operator!=(const FunctionOffset &compare) const {
  return !(*this == compare);
}

/**
 * It provides the possibility to compare two FunctionOffset.
 * This is used when the bimap will sort ProcessStates comparing them.
 * 
 * @param compare The FunctionOffset that will be compared with this.
 * @return True if this < fr1, False otherwise.
 */
bool FunctionOffset::operator<(const FunctionOffset &compare) const {
  return string(*this) < string(compare);
}