#include <iostream>
#include "Launcher.h"

using namespace std;

int main(int argc, const char** argv) {
	try {
		Launcher launcher(argc, argv);
		launcher.start();
	} catch (runtime_error& e) {
		cerr << "Error occurred: " << e.what() << endl;
	} catch (...) {
		cerr << "Generic error occurred" << endl;
	}
	return 0;
}
