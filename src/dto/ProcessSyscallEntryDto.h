#ifndef PTRACER_PROCESSSYSCALLENTRYDTO_H
#define PTRACER_PROCESSSYSCALLENTRYDTO_H

#include "../ProcessSyscallEntry.h"
#include "StackFrameDto.h"

class ProcessSyscallEntryDTO {
public:
	ProcessSyscallEntryDTO(const ProcessSyscallEntry& syscall);
	ProcessSyscallEntryDTO(const std::string flat, const std::string& executableName);
	[[nodiscard]] std::string serialize() const;
	bool operator==(const ProcessSyscallEntryDTO& that) const;
	bool operator!=(const ProcessSyscallEntryDTO& that) const;
	bool operator<(const ProcessSyscallEntryDTO& that) const;
private:
	static const std::string FIELD_SEPARATOR;
	static const std::string VALUE_SEPARATOR;
	static const std::string END_OF_OBJECT;
	std::string executableName;
	int syscall;
	std::vector<StackFrameDTO> frames;
};

#endif //PTRACER_PROCESSSYSCALLENTRYDTO_H
