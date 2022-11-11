#ifndef PTRACER_SYSCALLNAMERESOLVER_H
#define PTRACER_SYSCALLNAMERESOLVER_H

#include <map>
#include <string>

class SyscallNameResolver {
public:
	static std::string resolve(unsigned int syscallNumber);
private:
	static std::map<unsigned int, std::string> lookupTable;
	static void init();
};

#endif //PTRACER_SYSCALLNAMERESOLVER_H
