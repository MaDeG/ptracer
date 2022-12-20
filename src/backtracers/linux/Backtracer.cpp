#include "../../Backtracer.h"
#include "BacktracerImpl.h"

using namespace std;

unique_ptr<Backtracer> Backtracer::getInstance() {
	return std::unique_ptr<Backtracer>(new BacktracerImpl());
}