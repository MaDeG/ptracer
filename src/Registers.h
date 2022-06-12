/* 
 * Extension of the ptrace struct user_regs_struct in order to add some easy aliases that
 * facilitate the extraction of commonly used registers.
 */


#ifndef REGISTERS_H
#define REGISTERS_H
#include <sys/user.h>
#include <string>

class Registers : user_regs_struct {
public:
  unsigned long long int pc() const;
  unsigned long long int bp() const;
  unsigned long long int sp() const;
  int nsyscall() const;
  long long int ret_arg() const;
  unsigned long long int arg0() const;
  unsigned long long int arg1() const;
  unsigned long long int arg2() const;
  unsigned long long int arg3() const;
  unsigned long long int arg4() const;
  unsigned long long int arg5() const;
  operator std::string() const;
};

#endif /* REGISTERS_H */