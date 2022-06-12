/* 
 * This class is used to keep track and be able to sort function names and their associated
 * offset returned by libunwind as a backtrack entry.
 * The offset represent the difference between the return pointer located in the stack
 * and the function entry point.
 */

#ifndef FUNCTIONOFFSET_H
#define FUNCTIONOFFSET_H
#include <string>

class FunctionOffset {
public:
  static const std::string OFFSET_DELIMITER;
  FunctionOffset(const std::string function_name, const unsigned long long int offset);
  FunctionOffset(const long long int stack_pointer, const unsigned long long int offset);
  FunctionOffset(const std::string serialized);
  bool is_valid() const;
  operator std::string() const;
  bool operator==(const FunctionOffset& compare) const;
  bool operator!=(const FunctionOffset& compare) const;
  bool operator<(const FunctionOffset& compare) const;
private:
  std::string _function_name;
  long long int _stack_pointer;
  unsigned long long int _offset;
  bool _valid = false;

};

#endif /* FUNCTIONOFFSET_H */