#ifdef ANDROID

#ifndef PTRACER_BINDERDECODER_H
#define PTRACER_BINDERDECODER_H

#include <sys/types.h>
#include <linux/android/binder.h>
#include "SyscallDecoder.h"

enum binderCodes {
	FIRST_CALL_TRANSACTION = 0x00000001,
	LAST_CALL_TRANSACTION = 0x00ffffff,
	PING_TRANSACTION = B_PACK_CHARS('_', 'P', 'N', 'G'),
	START_RECORDING_TRANSACTION = B_PACK_CHARS('_', 'S', 'R', 'D'),
	STOP_RECORDING_TRANSACTION = B_PACK_CHARS('_', 'E', 'R', 'D'),
	DUMP_TRANSACTION = B_PACK_CHARS('_', 'D', 'M', 'P'),
	SHELL_COMMAND_TRANSACTION = B_PACK_CHARS('_', 'C', 'M', 'D'),
	INTERFACE_TRANSACTION = B_PACK_CHARS('_', 'N', 'T', 'F'),
	SYSPROPS_TRANSACTION = B_PACK_CHARS('_', 'S', 'P', 'R'),
	EXTENSION_TRANSACTION = B_PACK_CHARS('_', 'E', 'X', 'T'),
	DEBUG_PID_TRANSACTION = B_PACK_CHARS('_', 'P', 'I', 'D'),
	SET_RPC_CLIENT_TRANSACTION = B_PACK_CHARS('_', 'R', 'P', 'C'),
	// See android.os.IBinder.TWEET_TRANSACTION
	// Most importantly, messages can be anything not exceeding 130 UTF-8
	// characters, and callees should exclaim "jolly good message old boy!"
	TWEET_TRANSACTION = B_PACK_CHARS('_', 'T', 'W', 'T'),
	// See android.os.IBinder.LIKE_TRANSACTION
	// Improve binder self-esteem.
	LIKE_TRANSACTION = B_PACK_CHARS('_', 'L', 'I', 'K'),
	// Corresponds to TF_ONE_WAY -- an asynchronous call.
	FLAG_ONEWAY = 0x00000001,
	// Corresponds to TF_CLEAR_BUF -- clear transaction buffers after call
	// is made
	FLAG_CLEAR_BUF = 0x00000020,
	// Private userspace flag for transaction which is being requested from
	// a vendor context.
	FLAG_PRIVATE_VENDOR = 0x10000000,
};

struct BinderWriteReadData {
	binder_uintptr_t writeAddr;
	uint8_t* write;
	binder_size_t writeSize;
	std::unordered_map<binder_uintptr_t, uint8_t*> externalWriteBuffers;
	binder_uintptr_t readAddr;
	uint8_t* read;
	binder_size_t readSize;
	std::unordered_map<binder_uintptr_t, uint8_t*> externalReadBuffers;
	~BinderWriteReadData() {
		delete[] this->write;
		for (const auto& item: this->externalWriteBuffers) {
			delete[] item.second;
		}
		delete[] this->read;
		for (const auto& item: this->externalReadBuffers) {
			delete[] item.second;
		}
	}
};

struct BinderVersion {
	int version = -1;
	uint8_t* address = nullptr;
};

class BinderDecoder : public SyscallDecoder {
public:
	static void registerAt(ProcessSyscallDecoderMapper& mapper);
	bool decode(const ProcessSyscallEntry& syscall) override;
	bool decode(const ProcessSyscallExit& syscall) override;
	void printReport() const override;
private:
	static std::unordered_map<unsigned int, std::string> binderProtocols;
	static std::unordered_map<unsigned int, std::string> binderCodes;
	static std::set<int32_t> kernelHeaders;
	static std::set<std::pair<unsigned int, std::string>> transactionFlags;
	static std::set<std::pair<unsigned int, std::string>> flatBinderObjectFlags;
	BinderVersion binderVersion;
	std::vector<std::shared_ptr<BinderWriteReadData>> buffers;
	std::unordered_map<pid_t, std::shared_ptr<BinderWriteReadData>> activeCalls;
	static void initProtocols();
	static void initCodes();
	static void printTransaction(const binder_transaction_data* transactionData);
	static void printTransaction(const binder_transaction_data* transactionData, const std::unordered_map<binder_uintptr_t, uint8_t*>& buffers);
	static void printCommand(uint8_t const* const data, const binder_size_t size);
	static void printCommand(uint8_t const* const data, const binder_size_t size, const std::unordered_map<binder_uintptr_t, uint8_t*>& buffers);
	static void printReturn(uint8_t const* const data, const binder_size_t size);
	static void printReturn(uint8_t const* const data, const binder_size_t size, const std::unordered_map<binder_uintptr_t, uint8_t*>& buffers);
	static void printOffsets(const binder_transaction_data* transactionData, uint8_t const * const buffer, binder_uintptr_t const * const offsets);
	static void extractExternalWriteBuffers(uint8_t const* data,
																					binder_size_t size,
																					std::unordered_map<binder_uintptr_t, uint8_t*>& externalBuffers,
																					const Tracer& tracer);
	static void extractExternalReadBuffers(uint8_t const* data,
																				 binder_size_t size,
																				 std::unordered_map<binder_uintptr_t, uint8_t*>& externalBuffers,
																				 const Tracer& tracer);
	static std::string printFlags(unsigned int flags, const std::set<std::pair<unsigned int, std::string>>& definitions);
	static std::string printCode(unsigned int code);
	static std::string getMethodName(uint8_t const* const data, const binder_size_t size);
	bool handleWriteRead(const ProcessSyscallEntry& syscall);

};


#endif //PTRACER_BINDERDECODER_H

#endif // ANDROID