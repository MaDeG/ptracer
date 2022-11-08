/* 
 * Extension of the ptrace struct user_regs_struct in order to add some easy aliases that
 * facilitate the extraction of commonly used registers.
 */

#ifndef PTRACER_REGISTERS_H
#define PTRACER_REGISTERS_H
#include <sys/uio.h>
#include <sys/user.h>
#include <string>

class Registers : user_regs_struct {
public:
	static const unsigned short int ARGS_COUNT;
	Registers();
  unsigned long long int pc() const;
  unsigned long long int bp() const;
  unsigned long long int sp() const;
  unsigned int syscall() const;
  long long int returnValue() const;
  unsigned long long int argument(unsigned short int i) const;
	unsigned long long int flags() const;
	const iovec* getIovec() const;
  operator std::string() const;

private:
	const iovec io;
};

#endif /* PTRACER_REGISTERS_H */