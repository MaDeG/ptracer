#ifdef ANDROID

#include <boost/format.hpp>
#include <iostream>
#include <sys/syscall.h>
#include "BinderDecoder.h"
#include "../Tracer.h"
#include "../utils/Hexdump.hpp"

using namespace std;

unordered_map<unsigned int, string> BinderDecoder::binderProtocols;
unordered_map<unsigned int, string> BinderDecoder::binderCodes;
set<int32_t> BinderDecoder::kernelHeaders = { B_PACK_CHARS('V', 'N', 'D', 'R'),   // Android VNDK
                                              B_PACK_CHARS('R', 'E', 'C', 'O'),   // Android Recovery
                                              B_PACK_CHARS('S', 'Y', 'S', 'T') }; // Normal operations
set<pair<unsigned int, string>> BinderDecoder::transactionFlags = { pair<unsigned int, string>(TF_ONE_WAY, "TF_ONE_WAY"),
                                                                    pair<unsigned int, string>(TF_ROOT_OBJECT, "TF_ROOT_OBJECT"),
                                                                    pair<unsigned int, string>(TF_STATUS_CODE, "TF_STATUS_CODE"),
                                                                    pair<unsigned int, string>(TF_ACCEPT_FDS, "TF_ACCEPT_FDS"),
                                                                    pair<unsigned int, string>(TF_CLEAR_BUF, "TF_CLEAR_BUF") };
set<pair<unsigned int, string>> BinderDecoder::flatBinderObjectFlags = { pair<unsigned int, string>(FLAT_BINDER_FLAG_PRIORITY_MASK, "FLAT_BINDER_FLAG_PRIORITY_MASK"),
                                                                         pair<unsigned int, string>(FLAT_BINDER_FLAG_ACCEPTS_FDS, "FLAT_BINDER_FLAG_ACCEPTS_FDS"),
																																				 pair<unsigned int, string>(FLAT_BINDER_FLAG_SCHED_POLICY_MASK, "FLAT_BINDER_FLAG_SCHED_POLICY_MASK"),
																																				 pair<unsigned int, string>(FLAT_BINDER_FLAG_INHERIT_RT, "FLAT_BINDER_FLAG_INHERIT_RT"),
																																				 pair<unsigned int, string>(FLAT_BINDER_FLAG_TXN_SECURITY_CTX, "FLAT_BINDER_FLAG_TXN_SECURITY_CTX"),
																																				 pair<unsigned int, string>(BINDER_BUFFER_FLAG_HAS_PARENT, "BINDER_BUFFER_FLAG_HAS_PARENT")};

void BinderDecoder::registerAt(ProcessSyscallDecoderMapper& mapper) {
	if (BinderDecoder::binderProtocols.empty()) {
		BinderDecoder::initProtocols();
	}
	if (BinderDecoder::binderCodes.empty()) {
		BinderDecoder::initCodes();
	}
	shared_ptr<SyscallDecoder> thisDecoder(new BinderDecoder());
	mapper.registerEntrySyscallDecoder(SYS_ioctl, thisDecoder);
	mapper.registerExitSyscallDecoder(SYS_ioctl, thisDecoder);
}

bool BinderDecoder::decode(const ProcessSyscallEntry& syscall) {
	if (syscall.argument(1) != BINDER_WRITE_READ && syscall.argument(1) != BINDER_VERSION) {
		// Only R/W requests are handled
		return true;
	}
	if (syscall.argument(1) == BINDER_VERSION) {
		this->binderVersion.address = (uint8_t*) (syscall.argument(2));
		return true;
	}
	this->handleWriteRead(syscall);
	return true;
}

bool BinderDecoder::decode(const ProcessSyscallExit& syscall) {
	if (this->binderVersion.version == -1 && this->binderVersion.address) {
		binder_version* version = (binder_version*) (syscall.getTracer()->extractBytes((unsigned long long int) (this->binderVersion.address), sizeof(binder_version)));
		this->binderVersion.version = version->protocol_version;
		delete version;
		return true;
	}
	auto it = this->activeCalls.find(syscall.getSpid());
	if (it == this->activeCalls.end()) {
		// Not interested in this call
		return true;
	}
	shared_ptr<BinderWriteReadData>& bwrd = it->second;
	// Write buffer can be skipped because it contains commands for the Binder driver and has already been read during the entry notification
	if (bwrd->readAddr && bwrd->readSize > 0) {
		bwrd->read = (uint8_t*) (syscall.getTracer()->extractBytes(bwrd->readAddr, bwrd->readSize));
		if (bwrd->read != nullptr) {
			BinderDecoder::extractExternalReadBuffers(bwrd->read, bwrd->readSize, bwrd->externalReadBuffers, *syscall.getTracer());
		}
	}
	return true;
}

void BinderDecoder::printReport() const {
	cout << "------------------ BINDER DECODER START ------------------" << endl;
	if (this->binderVersion.version >= 0) {
		cout << "Protocol version: " << this->binderVersion.version << endl;
	}
	for (const shared_ptr<BinderWriteReadData>& i : this->buffers) {
		cout << "------------------ BINDER CALL START ------------------" << endl;
		if (i->write) {
			cout << "Sent:" << endl;
			BinderDecoder::printCommand(i->write, i->writeSize, i->externalWriteBuffers);
		}
		if (i->write && i->read) {
			cout << endl;
		}
		if (i->read) {
			cout << "Received:" << endl;
			BinderDecoder::printReturn(i->read, i->readSize, i->externalReadBuffers);
		}
		cout << "------------------ BINDER CALL STOP -------------------" << endl;
	}
	cout << "------------------ BINDER DECODER STOP -------------------" << endl;
}

bool BinderDecoder::handleWriteRead(const ProcessSyscallEntry& syscall) {
	assert(syscall.argument(1) == BINDER_WRITE_READ);
	shared_ptr<BinderWriteReadData> data = make_shared<BinderWriteReadData>();
	binder_write_read* request = (binder_write_read*) (syscall.getTracer()->extractBytes(syscall.argument(2), sizeof(binder_write_read)));
	if (request->write_buffer && request->write_size > 0) {
		data->writeAddr = request->write_buffer + request->write_consumed;
		data->write = (uint8_t*) (syscall.getTracer()->extractBytes(request->write_buffer, request->write_size) + request->write_consumed);
		if (data->write != nullptr) {
			data->writeSize = request->write_size;
			BinderDecoder::extractExternalWriteBuffers(data->write, data->writeSize, data->externalWriteBuffers, *syscall.getTracer());
		}
	}
	if (request->read_buffer && request->read_size > 0) {
		// This buffer will be read at the syscall exit notification
		data->readAddr = request->read_buffer + request->read_consumed;
		data->readSize = request->read_size;
	}
	delete request;
	this->activeCalls[syscall.getSpid()] = data;
	this->buffers.push_back(move(data));
	return true;
}

void BinderDecoder::printTransaction(const binder_transaction_data* transactionData) {
	BinderDecoder::printTransaction(transactionData, unordered_map<binder_uintptr_t, uint8_t*>());
}

void BinderDecoder::printTransaction(const binder_transaction_data* transactionData, const unordered_map<binder_uintptr_t, uint8_t*>& buffers) {
	cout << "Target: " << boost::format("0x%x") % transactionData->target.ptr << " (" << transactionData->target.handle << ")" << endl;
	if (transactionData->cookie) {
		cout << "Cookie: " << boost::format("0x%x") % transactionData->cookie << endl;
	}
	if (transactionData->code) {
		cout << "Code: " << BinderDecoder::printCode(transactionData->code) << endl;
	}
	if (transactionData->flags) {
		cout << "Flags: " << BinderDecoder::printFlags(transactionData->flags, BinderDecoder::transactionFlags) << endl;
	}
	if (transactionData->sender_pid) {
		cout << "Sender PID: " << transactionData->sender_pid << endl;
	}
	if (transactionData->sender_euid) {
		cout << "Sender EUID: " << transactionData->sender_euid << endl;
	}
	if (transactionData->data.ptr.buffer) {
		cout << "Buffer pointer: " << boost::format("0x%x") % transactionData->data.ptr.buffer
		     << " (" << transactionData->data.ptr.buffer << "), Data size: " << transactionData->data_size << endl;
	}
	auto itBuf = buffers.find(transactionData->data.ptr.buffer);
	if (itBuf != buffers.end()) {
		cout << "Buffer content:" << endl << Hexdump(itBuf->second, transactionData->data_size, (const void*) transactionData->data.ptr.buffer);
		string method = BinderDecoder::getMethodName(itBuf->second, transactionData->data_size);
		if (!method.empty()) {
			cout << "Interface: " << method << endl;
		}
	}
	if (transactionData->data.ptr.offsets) {
		cout << "Offsets pointer: " << boost::format("0x%x") % transactionData->data.ptr.offsets << " ("
		     << transactionData->data.ptr.offsets << "), Offsets size: " << transactionData->offsets_size << endl;
	}
	auto itOff = buffers.find(transactionData->data.ptr.offsets);
	if (itOff != buffers.end()) {
		cout << "Offsets content:" << endl << Hexdump(itOff->second, transactionData->offsets_size, (const void*) transactionData->data.ptr.offsets);
		if (itBuf != buffers.end()) {
			if (transactionData->offsets_size <= 0 || transactionData->offsets_size % sizeof(binder_uintptr_t) != 0) {
				cerr << "Malformed offsets format" << endl;
				return;
			}
			printOffsets(transactionData, (uint8_t*) itBuf->second, (binder_uintptr_t*) itOff->second);
		}
	}
}

void BinderDecoder::printOffsets(const binder_transaction_data* transactionData, uint8_t const * const buffer, binder_uintptr_t const * const offsets) {
	for (int i = 0; i < transactionData->offsets_size / 8; i++) {
		binder_uintptr_t offset = *(offsets + i);
		if (offset >= transactionData->data_size) {
			// Malformed offset, skip it
			return;
		}
		cout << "Offset " << i << ":" << endl;
		auto* hdr = (binder_object_header*) (offset + buffer);
		cout << "Type: " << boost::format("0x%x") % hdr->type << " (" << binderProtocols[hdr->type] << ")" << endl;
		// TODO: What if the buffer size truncates a structure?
		switch (hdr->type) {
			case BINDER_TYPE_BINDER:
			case BINDER_TYPE_WEAK_BINDER: {
				auto* obj = (flat_binder_object*) hdr;
				if (obj->flags) {
					cout << "Flags: " << printFlags(obj->flags, flatBinderObjectFlags) << endl;
				}
				cout << "Binder: " << boost::format("0x%x") % obj->binder << " (" << obj->binder << ")" << endl;
				if (obj->cookie) {
					cout << "Cookie: " << boost::format("0x%x") % obj->cookie << "(" << obj->cookie << ")" << endl;
				}
			} break;
			case BINDER_TYPE_HANDLE:
			case BINDER_TYPE_WEAK_HANDLE: {
				auto* obj = (flat_binder_object*) hdr;
				if (obj->flags) {
					cout << "Flags: " << printFlags(obj->flags, flatBinderObjectFlags) << endl;
				}
				cout << "Handle: " << obj->handle << endl;
				if (obj->cookie) {
					cout << "Cookie: " << boost::format("0x%x") % obj->cookie << "(" << obj->cookie << ")" << endl;
				}
			} break;
			case BINDER_TYPE_FD: {
				auto* obj = (binder_fd_object*) hdr;
				cout << "File Descriptor: " << obj->fd << endl;
				if (obj->cookie) {
					cout << "Cookie: " << boost::format("0x%x") % obj->cookie << endl;
				}
			} break;
			case BINDER_TYPE_FDA: {
				auto* obj = (binder_fd_array_object*) hdr;
				cout << "File descriptor array length: " << obj->num_fds << endl;
				cout << "Parent: " << obj->parent << endl;
				cout << "Parent offset: " << obj->parent_offset << endl;
			} break;
			case BINDER_TYPE_PTR: {
				auto* obj = (binder_buffer_object*) hdr;
				if (obj->flags) {
					cout << "Flags: " << printFlags(obj->flags, flatBinderObjectFlags) << endl;
				}
				cout << "Buffer: " << boost::format("0x%x") % obj->buffer << " (" << obj->buffer << ")" << endl;
				cout << "Length: " << obj->length << endl;
				cout << "Parent: " << obj->parent << endl;
				cout << "Parent offset: " << obj->parent_offset << endl;
			} break;
			default:
				cout << "Unknown type" << endl;
				break;
		}
	}
}

void BinderDecoder::printCommand(uint8_t const* const data, const binder_size_t size, const unordered_map<binder_uintptr_t, uint8_t*>& buffers) {
	auto const* ptr = data;
	uint8_t const* const end = data + size;
	while (ptr < end && *((uint32_t*) ptr) != 0) {
		const binder_driver_command_protocol& protocol = *(const binder_driver_command_protocol*)(ptr);
		cout << "Protocol: " << boost::format("0x%x") % protocol << " (" << BinderDecoder::binderProtocols[protocol] << ")" << endl;
		ptr += sizeof(protocol);
		switch (protocol) {
			case BC_TRANSACTION:
			case BC_REPLY: {
				const auto* transactionData = (const binder_transaction_data*) (ptr);
				BinderDecoder::printTransaction(transactionData, buffers);
				ptr += sizeof(binder_transaction_data);
			} break;
			case BC_ACQUIRE_RESULT: {
				const int32_t res = *(int32_t const*)(ptr);
				cout << "Result: " << res << (res ? " (SUCCESS)" : " (FAILURE)") << endl;
				ptr += sizeof(res);
			} break;
			case BC_FREE_BUFFER: {
				const auto& buf = *(binder_uintptr_t const*) (ptr);
				cout << "Buffer: " << boost::format("0x%x") % buf << " (" << buf << ")" << endl;
				ptr += sizeof(buf);
			}	break;
			case BC_INCREFS:
			case BC_ACQUIRE:
			case BC_RELEASE:
			case BC_DECREFS: {
				const int32_t handle = *(int32_t const*) (ptr);
				cout << "Handle: " << handle << endl;
				ptr += sizeof(handle);
			} break;
			case BC_INCREFS_DONE:
			case BC_ACQUIRE_DONE: {
				const auto& cookie = *(binder_ptr_cookie const*) (ptr);
				cout << "Target: " << cookie.ptr << ", Cookie: " << cookie.cookie << endl;
				ptr += sizeof(cookie);
			}	break;
			case BC_ATTEMPT_ACQUIRE: {
				const binder_pri_desc& desc = *(binder_pri_desc const*) (ptr);
				cout << "Description: " << desc.desc << ", Priority: " << desc.priority << endl;
				ptr += sizeof(desc);
			}	break;
			case BC_REQUEST_DEATH_NOTIFICATION:
			case BC_CLEAR_DEATH_NOTIFICATION: {
				const binder_handle_cookie& handle = *(binder_handle_cookie const*) (ptr);
				cout << "Handle: " << handle.handle << ", Death cookie: " << handle.cookie << endl;
				ptr += sizeof(handle);
			}	break;
			case BC_DEAD_BINDER_DONE: {
				const auto& death = *(binder_uintptr_t const*) (ptr);
				cout << "Death cookie " << death << endl;
				ptr += sizeof (death);
			} break;
			case BC_TRANSACTION_SG:
			case BC_REPLY_SG: {
				const binder_transaction_data_sg& transaction = *(binder_transaction_data_sg const*) (ptr);
				cout << "Buffers size: " << transaction.buffers_size << endl;
				BinderDecoder::printTransaction(&transaction.transaction_data, buffers);
				ptr += sizeof(transaction);
			}	break;
			default:
				// No details to show for: BC_REGISTER_LOOPER, BC_ENTER_LOOPER, BC_EXIT_LOOPER
				break;
		}
	}
	assert(ptr <= end);
}

void BinderDecoder::printReturn(uint8_t const* const data, const binder_size_t size) {
	BinderDecoder::printReturn(data, size, unordered_map<binder_uintptr_t, uint8_t*>());
}

void BinderDecoder::printReturn(uint8_t const* const data, const binder_size_t size, const unordered_map<binder_uintptr_t, uint8_t*>& buffers) {
	auto const* ptr = data;
	uint8_t const* const end = data + size;
	while (ptr < end && *((uint32_t*) ptr) != 0) {
		const binder_driver_return_protocol& protocol = *(const binder_driver_return_protocol*)(ptr);
		cout << "Protocol: " << boost::format("0x%x") % protocol << " (" << BinderDecoder::binderProtocols[protocol] << ")" << endl;
		ptr += sizeof(protocol);
		switch (protocol) {
			case BR_ERROR: {
				const int32_t err = *(int32_t const*) (ptr);
				cout << "Error: " << err << endl;
				ptr += sizeof(err);
			} break;
			case BR_TRANSACTION_SEC_CTX: {
				auto const* transactionSecctx = (binder_transaction_data_secctx const*) (ptr);
				BinderDecoder::printTransaction(&transactionSecctx->transaction_data, buffers);
				cout << "Security context: " << boost::format("0x%x") % transactionSecctx->secctx << endl;
				ptr += sizeof(binder_transaction_data_secctx);
			} break;
			case BR_TRANSACTION:
			case BR_REPLY: {
				const auto* transactionData = (const binder_transaction_data*) (ptr);
				BinderDecoder::printTransaction(transactionData, buffers);
				ptr += sizeof(binder_transaction_data);
				} break;
			case BR_ACQUIRE_RESULT: {
				const int32_t res = *(int32_t const*) (ptr);
				cout << "Result: " << res << (res ? " (SUCCESS)" : " (FAILURE)") << endl;
				ptr += sizeof(res);
			} break;
			case BR_INCREFS:
			case BR_ACQUIRE:
			case BR_RELEASE:
			case BR_DECREFS:
			case BR_ATTEMPT_ACQUIRE: {
				const auto& cookie = *(binder_ptr_cookie const*) (ptr);
				cout << "Target: " << cookie.ptr << ", Cookie: " << cookie.cookie << endl;
				ptr += sizeof(cookie);
			} break;
			case BR_DEAD_BINDER:
			case BR_CLEAR_DEATH_NOTIFICATION_DONE: {
				const auto& death = *(const binder_uintptr_t*) (ptr);
				cout << "Death notification: " << death << endl;
				ptr += sizeof(death);
			} break;
			default:
				// No details to show for: BR_OK, BR_NOOP, BR_DEAD_REPLY, BR_TRANSACTION_COMPLETE, BR_NOOP, BR_SPAWN_LOOPER, BR_FINISHED
				// In this case no incrememnt is needed, they do not have body
				break;
		}
	}
	assert(ptr <= end);
}

void BinderDecoder::initProtocols() {
	// Command strings
	BinderDecoder::binderProtocols[BC_TRANSACTION] = "BC_TRANSACTION";
	BinderDecoder::binderProtocols[BC_REPLY] = "BC_REPLY";
	BinderDecoder::binderProtocols[BC_ACQUIRE_RESULT] = "BC_ACQUIRE_RESULT";
	BinderDecoder::binderProtocols[BC_FREE_BUFFER] = "BC_FREE_BUFFER";
	BinderDecoder::binderProtocols[BC_INCREFS] = "BC_INCREFS";
	BinderDecoder::binderProtocols[BC_ACQUIRE] = "BC_ACQUIRE";
	BinderDecoder::binderProtocols[BC_RELEASE] = "BC_RELEASE";
	BinderDecoder::binderProtocols[BC_DECREFS] = "BC_DECREFS";
	BinderDecoder::binderProtocols[BC_INCREFS_DONE] = "BC_INCREFS_DONE";
	BinderDecoder::binderProtocols[BC_ACQUIRE_DONE] = "BC_ACQUIRE_DONE";
	BinderDecoder::binderProtocols[BC_ATTEMPT_ACQUIRE] = "BC_ATTEMPT_ACQUIRE";
	BinderDecoder::binderProtocols[BC_REGISTER_LOOPER] = "BC_REGISTER_LOOPER";
	BinderDecoder::binderProtocols[BC_ENTER_LOOPER] = "BC_ENTER_LOOPER";
	BinderDecoder::binderProtocols[BC_EXIT_LOOPER] = "BC_EXIT_LOOPER";
	BinderDecoder::binderProtocols[BC_REQUEST_DEATH_NOTIFICATION] = "BC_REQUEST_DEATH_NOTIFICATION";
	BinderDecoder::binderProtocols[BC_CLEAR_DEATH_NOTIFICATION] = "BC_CLEAR_DEATH_NOTIFICATION";
	BinderDecoder::binderProtocols[BC_DEAD_BINDER_DONE] = "BC_DEAD_BINDER_DONE";
	BinderDecoder::binderProtocols[BC_TRANSACTION_SG] = "BC_TRANSACTION_SG";
	BinderDecoder::binderProtocols[BC_REPLY_SG] = "BC_REPLY_SG";
	// Return strings
	BinderDecoder::binderProtocols[BR_ERROR] = "BR_ERROR";
	BinderDecoder::binderProtocols[BR_OK] = "BR_OK";
	BinderDecoder::binderProtocols[BR_TRANSACTION] = "BR_TRANSACTION";
	BinderDecoder::binderProtocols[BR_REPLY] = "BR_REPLY";
	BinderDecoder::binderProtocols[BR_ACQUIRE_RESULT] = "BR_ACQUIRE_RESULT";
	BinderDecoder::binderProtocols[BR_DEAD_REPLY] = "BR_DEAD_REPLY";
	BinderDecoder::binderProtocols[BR_TRANSACTION_COMPLETE] = "BR_TRANSACTION_COMPLETE";
	BinderDecoder::binderProtocols[BR_INCREFS] = "BR_INCREFS";
	BinderDecoder::binderProtocols[BR_ACQUIRE] = "BR_ACQUIRE";
	BinderDecoder::binderProtocols[BR_RELEASE] = "BR_RELEASE";
	BinderDecoder::binderProtocols[BR_DECREFS] = "BR_DECREFS";
	BinderDecoder::binderProtocols[BR_ATTEMPT_ACQUIRE] = "BR_ATTEMPT_ACQUIRE";
	BinderDecoder::binderProtocols[BR_NOOP] = "BR_NOOP";
	BinderDecoder::binderProtocols[BR_SPAWN_LOOPER] = "BR_SPAWN_LOOPER";
	BinderDecoder::binderProtocols[BR_FINISHED] = "BR_FINISHED";
	BinderDecoder::binderProtocols[BR_DEAD_BINDER] = "BR_DEAD_BINDER";
	BinderDecoder::binderProtocols[BR_CLEAR_DEATH_NOTIFICATION_DONE] = "BR_CLEAR_DEATH_NOTIFICATION_DONE";
	BinderDecoder::binderProtocols[BR_FAILED_REPLY] = "BR_FAILED_REPL";
	// Flat binder types
	BinderDecoder::binderProtocols[BINDER_TYPE_BINDER] = "BINDER_TYPE_BINDER";
	BinderDecoder::binderProtocols[BINDER_TYPE_WEAK_BINDER] = "BINDER_TYPE_WEAK_BINDER";
	BinderDecoder::binderProtocols[BINDER_TYPE_HANDLE] = "BINDER_TYPE_HANDLE";
	BinderDecoder::binderProtocols[BINDER_TYPE_WEAK_HANDLE] = "BINDER_TYPE_WEAK_HANDLE";
	BinderDecoder::binderProtocols[BINDER_TYPE_FD] = "BINDER_TYPE_FD"; 
	BinderDecoder::binderProtocols[BINDER_TYPE_FDA] = "BINDER_TYPE_FDA";
	BinderDecoder::binderProtocols[BINDER_TYPE_PTR] = "BINDER_TYPE_PTR";
}

void BinderDecoder::initCodes() {
	BinderDecoder::binderCodes[FIRST_CALL_TRANSACTION] = "FIRST_CALL_TRANSACTION";
	BinderDecoder::binderCodes[LAST_CALL_TRANSACTION] = "LAST_CALL_TRANSACTION";
	BinderDecoder::binderCodes[PING_TRANSACTION] = "PING_TRANSACTION";
	BinderDecoder::binderCodes[START_RECORDING_TRANSACTION] = "START_RECORDING_TRANSACTION";
	BinderDecoder::binderCodes[STOP_RECORDING_TRANSACTION] = "STOP_RECORDING_TRANSACTION";
	BinderDecoder::binderCodes[DUMP_TRANSACTION] = "DUMP_TRANSACTION";
	BinderDecoder::binderCodes[SHELL_COMMAND_TRANSACTION] = "SHELL_COMMAND_TRANSACTION";
	BinderDecoder::binderCodes[INTERFACE_TRANSACTION] = "INTERFACE_TRANSACTION";
	BinderDecoder::binderCodes[SYSPROPS_TRANSACTION] = "SYSPROPS_TRANSACTION";
	BinderDecoder::binderCodes[EXTENSION_TRANSACTION] = "EXTENSION_TRANSACTION";
	BinderDecoder::binderCodes[DEBUG_PID_TRANSACTION] = "DEBUG_PID_TRANSACTION";
	BinderDecoder::binderCodes[SET_RPC_CLIENT_TRANSACTION] = "SET_RPC_CLIENT_TRANSACTION";
	BinderDecoder::binderCodes[TWEET_TRANSACTION] = "TWEET_TRANSACTION";
	BinderDecoder::binderCodes[LIKE_TRANSACTION] = "LIKE_TRANSACTION";
	BinderDecoder::binderCodes[FLAG_ONEWAY] = "FLAG_ONEWAY";
	BinderDecoder::binderCodes[FLAG_CLEAR_BUF] = "FLAG_CLEAR_BUF";
	BinderDecoder::binderCodes[FLAG_PRIVATE_VENDOR] = "FLAG_PRIVATE_VENDOR";
}

void BinderDecoder::extractExternalWriteBuffers(uint8_t const* data, binder_size_t size, unordered_map<binder_uintptr_t, uint8_t*>& externalBuffers, const Tracer& tracer) {
	auto const* ptr = data;
	uint8_t const* const end = data + size;
	while (ptr < end && *((uint32_t*) ptr) != 0) {
		const auto& protocol = *(const binder_driver_command_protocol*) (ptr);
		ptr += sizeof(protocol);
		binder_transaction_data const* transaction = nullptr;
		switch (protocol) {
			case BC_TRANSACTION_SG: //TODO: Extra considerations might be needed for this type
			case BC_REPLY_SG: {
				const auto* transactionSg = (binder_transaction_data_sg const*) (ptr);
				transaction = &transactionSg->transaction_data;
				ptr += sizeof(binder_transaction_data_sg);
			} break;
			case BC_TRANSACTION:
			case BC_REPLY: {
				transaction = (const binder_transaction_data*) (ptr);
				ptr += sizeof(binder_transaction_data);
			} break;
			case BC_ACQUIRE_RESULT:
			case BC_INCREFS:
			case BC_ACQUIRE:
			case BC_RELEASE:
			case BC_DECREFS:
				ptr += sizeof(int32_t);
				break;
			case BC_INCREFS_DONE:
			case BC_ACQUIRE_DONE:
				ptr += sizeof(binder_ptr_cookie);
			  break;
			case BC_ATTEMPT_ACQUIRE:
				ptr += sizeof(binder_pri_desc);
				break;
			case BC_REQUEST_DEATH_NOTIFICATION:
			case BC_CLEAR_DEATH_NOTIFICATION:
				ptr += sizeof(binder_handle_cookie);
				break;
			case BC_FREE_BUFFER:
			case BC_DEAD_BINDER_DONE:
				ptr += sizeof (binder_uintptr_t);
			  break;
			default:
				// In this case no incrememnt is needed, they do not have body
				break;
		}
		if (transaction) {
			if (transaction->data.ptr.buffer && transaction->data_size > 0) {
				auto* buffer = (uint8_t*) (tracer.extractBytes(transaction->data.ptr.buffer, transaction->data_size));
				if (buffer != nullptr) {
					externalBuffers[transaction->data.ptr.buffer] = buffer;
				}
			}
			if (transaction->data.ptr.offsets && transaction->offsets_size > 0) {
				auto* buffer = (uint8_t*) (tracer.extractBytes(transaction->data.ptr.offsets, transaction->offsets_size));
				if (buffer != nullptr) {
					externalBuffers[transaction->data.ptr.offsets] = buffer;
				}
			}
		}
	}
	assert(ptr <= end);
}

void BinderDecoder::extractExternalReadBuffers(uint8_t const* data, binder_size_t size, unordered_map<binder_uintptr_t, uint8_t*>& externalBuffers, const Tracer& tracer) {
	auto const* ptr = data;
	uint8_t const* const end = data + size;
	while (ptr < end && *((uint32_t*) ptr) != 0) {
		const auto& protocol = *(const binder_driver_return_protocol*) (ptr);
		ptr += sizeof(protocol);
		binder_transaction_data const* transaction = nullptr;
		switch (protocol) {
			case BR_TRANSACTION_SEC_CTX: {
				auto const* transactionSecctx = (binder_transaction_data_secctx const*) (ptr);
				transaction = &transactionSecctx->transaction_data;
				ptr += sizeof(binder_transaction_data_secctx);
			} break;
			case BR_TRANSACTION:
			case BR_REPLY: {
				transaction = (binder_transaction_data const*) (ptr);
				ptr += sizeof(binder_transaction_data);
			} break;
			case BR_ERROR:
			case BR_ACQUIRE_RESULT:
				ptr += sizeof(int32_t);
				break;
			case BR_INCREFS:
			case BR_ACQUIRE:
			case BR_RELEASE:
			case BR_DECREFS:
			case BR_ATTEMPT_ACQUIRE:
				ptr += sizeof(binder_ptr_cookie);
				break;
			case BR_DEAD_BINDER:
			case BR_CLEAR_DEATH_NOTIFICATION_DONE:
				ptr += sizeof(binder_uintptr_t);
				break;
			default:
				// In this case no incrememnt is needed, they do not have body
				break;
		}
		if (transaction) {
			if (transaction->data.ptr.buffer && transaction->data_size > 0) {
				auto* buffer = (uint8_t*) (tracer.extractBytes(transaction->data.ptr.buffer, transaction->data_size));
				if (buffer != nullptr) {
					externalBuffers[transaction->data.ptr.buffer] = buffer;
				}
			}
			if (transaction->data.ptr.offsets && transaction->offsets_size > 0) {
				auto* buffer = (uint8_t*) (tracer.extractBytes(transaction->data.ptr.offsets, transaction->offsets_size));
				if (buffer != nullptr) {
					externalBuffers[transaction->data.ptr.offsets] = buffer;
				}
			}
		}
	}
	assert(ptr <= end);
}

string BinderDecoder::printFlags(unsigned int flags, const set<pair<unsigned int, std::string>>& definitions) {
	string out = to_string(flags);
	vector<string> flagStrings;
	for (const auto& item: definitions) {
		if (flags & item.first) {
			flagStrings.push_back(item.second);
		}
	}
	if (!flagStrings.empty()) {
		out += " (";
		for (string& i: flagStrings) {
			out += i + " | ";
		}
		out.resize(out.size() - 3);
		out += ")";
	}
	return out;
}

string BinderDecoder::printCode(unsigned int code) {
	string out = to_string(code);
	auto it = BinderDecoder::binderCodes.find(code);
	if (it != BinderDecoder::binderCodes.end()) {
		out += " (" + it->second + ")";
	}
	return out;
}

// TODO: For now we try to understand from here if the transaction is an INTERFACE_TRANSACTION and hence
// TODO: only contains a 16 bit per char string or if it is a normal transaction and contains the extra fields
// TODO: at the start as implemented in Parcel.cpp
string BinderDecoder::getMethodName(uint8_t const* const data, const binder_size_t size) {
	string out;
	uint16_t* strPtr;
	if(size >= 16 && BinderDecoder::kernelHeaders.contains(* (int32_t*) (data + 8))) {
		strPtr = (uint16_t*) (data + 12);
	} else {
		strPtr = (uint16_t*) (data);
	}
	int strLength = * (int32_t*) strPtr;
	strPtr += 2;
	if (strLength > size) {
		// Malformed data
		return out;
	}
	uint16_t const * const strEnd = strPtr + strLength;
	while (strPtr < strEnd) {
		// TODO: Java Strings are UTF-16, here they are interpreted as ASCII
		out += ((char) *strPtr++);
	}
	return out;
}

#endif