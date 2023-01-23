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
	return (boost::format("Registers = { PC: %#018x\tSP: %#018x\tRET: %#018x }") % this->pc() % this->sp() % this->returnValue()).str();
}