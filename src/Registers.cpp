#include <boost/format.hpp>
#include "Registers.h"

using namespace std;

const iovec* Registers::getIovec() const {
	return &this->io;
}

/**
 * Defines the object string conversion.
 * It captures only the most important values.
 *
 * @return The string representation of this object.
 */
Registers::operator string() const {
	return (boost::format("Registers = { PC: %#016x\tSP: %#016x\tRET: %#016x }") % this->pc() % this->sp() % this->returnValue()).str();
}