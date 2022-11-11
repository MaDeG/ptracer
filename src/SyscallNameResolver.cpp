#include "SyscallNameResolver.h"

using namespace std;

map<unsigned int, string> SyscallNameResolver::lookupTable;

string SyscallNameResolver::resolve(unsigned int syscallNumber) {
	if (SyscallNameResolver::lookupTable.empty()) {
		SyscallNameResolver::init();
	}
	return SyscallNameResolver::lookupTable[syscallNumber];
}