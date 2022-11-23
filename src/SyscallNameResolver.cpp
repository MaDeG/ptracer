#include "SyscallNameResolver.h"

using namespace std;

map<unsigned int, string> SyscallNameResolver::lookupTable;

/**
 * Transforms a syscall number in a syscall name depending on the running architecture.
 *
 * @param syscallNumber The syscall number that will be transformed
 * @return The name of the syscall corresponding to the passed syscall number.
 */
string SyscallNameResolver::resolve(unsigned int syscallNumber) {
	if (SyscallNameResolver::lookupTable.empty()) {
		SyscallNameResolver::init();
	}
	return SyscallNameResolver::lookupTable[syscallNumber];
}