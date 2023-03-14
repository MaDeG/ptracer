#ifndef PTRACER_HEXDUMP_HPP
#define PTRACER_HEXDUMP_HPP

#include <cctype>
#include <iomanip>
#include <ostream>

using namespace std;

template<unsigned RowSize, bool ShowAscii>
struct CustomHexdump {
	CustomHexdump(const void* data, unsigned length) : CustomHexdump(data, length, nullptr) {}
	CustomHexdump(const void* data, unsigned length, const void* realAddr) : mData((const unsigned char*) (data)),
																																					 mLength(length),
																																					 realAddr((unsigned long long) (realAddr)) {}
	const unsigned char* mData;
	const unsigned mLength;
	const unsigned long long realAddr;
};

template<unsigned RowSize, bool ShowAscii>
ostream& operator <<(ostream& out, const CustomHexdump<RowSize, ShowAscii>& dump) {
	ios_base::fmtflags f(out.flags());
	out.fill('0');
	for (int i = 0; i < dump.mLength; i += RowSize) {
		out << "0x" << setw(6) << hex << i + dump.realAddr << ": ";
		for (int j = 0; j < RowSize; ++j) {
			if (j && j % 8 == 0) {
				out << " ";
			}
			if (i + j < dump.mLength) {
				out << hex << setw(2) << static_cast<int>(dump.mData[i + j]) << " ";
			} else {
				out << "   ";
			}
		}

		out << " ";
		if (ShowAscii) {
			for (int j = 0; j < RowSize; ++j) {
				if (j && j % 8 == 0) {
					out << " ";
				}
				if (i + j < dump.mLength) {
					if (isprint(dump.mData[i + j])) {
						out << static_cast<char>(dump.mData[i + j]);
					} else {
						out << ".";
					}
				}
			}
		}
		out << endl;
	}
	out.flags(f);
	return out;
}

typedef CustomHexdump<16, true> Hexdump;

#endif //PTRACER_HEXDUMP_HPP
