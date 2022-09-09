#include <iostream>
#include "Launcher.h"

int main(int argc, const char** argv) {
	try {
		Launcher launcher(argc, argv);
		launcher.start();
	} catch (const std::runtime_error& e) {
		std::cout << "Error occurred: " << e.what() << std::endl;
	}
	return 0;
}
