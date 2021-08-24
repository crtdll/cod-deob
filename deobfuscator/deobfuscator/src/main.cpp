#include "stdafx.h"
#include <vector>
#include <fstream>
#include <unordered_map>
#include <sstream>

#define MAX_JMP_SIZE_DETECTION (200) // max size a jmp near can be (leave if you're not sure what this is)

enum eInstructions {
	PUSH_NONE,
	PUSH_PAIR = 0x41,
	PUSH_RAX = 0x50,
	PUSH_RCX,
	PUSH_RDX,
	PUSH_RBX,
	PUSH_RSP,
	PUSH_RBP,
	PUSH_RSI,
	PUSH_RDI,
	POP_RAX,
	POP_RCX,
	POP_RDX,
	POP_RBX,
	POP_RSP,
	POP_RBP,
	POP_RSI,
	POP_RDI,
	PUSH_R8 = 0x50,
	PUSH_R9,
	PUSH_R10,
	PUSH_R11,
	PUSH_R12,
	PUSH_R13,
	PUSH_R14,
	PUSH_R15,
	POP_R8,
	POP_R9,
	POP_R10,
	POP_R11,
	POP_R12,
	POP_R13,
	POP_R14,
	POP_R15,
	PUSHFQ = 0x9C,
	POPFQ = 0x9D,
	JMP_NEAR = 0xEB
};

std::vector<std::pair<std::pair<uint8_t, uint8_t>, std::pair<uint8_t, uint8_t>>> push_pops = {
	{ { PUSH_RAX, PUSH_NONE }, { POP_RAX, PUSH_NONE } },	// rax
	{ { PUSH_RCX, PUSH_NONE }, { POP_RCX, PUSH_NONE } },	// rcx
	{ { PUSH_RDX, PUSH_NONE }, { POP_RDX, PUSH_NONE } },	// rdx
	{ { PUSH_RBX, PUSH_NONE }, { POP_RBX, PUSH_NONE } },	// rbx
	{ { PUSH_RSP, PUSH_NONE }, { POP_RSP, PUSH_NONE } },	// rsp
	{ { PUSH_RBP, PUSH_NONE }, { POP_RBP, PUSH_NONE } },	// rbp
	{ { PUSH_RSI, PUSH_NONE }, { POP_RSI, PUSH_NONE } },	// rsi
	{ { PUSH_RDI, PUSH_NONE }, { POP_RDI, PUSH_NONE } },	// rdi
	{ { PUSH_PAIR, PUSH_R8 }, { PUSH_PAIR, POP_R8 } },		// r8
	{ { PUSH_PAIR, PUSH_R9 }, { PUSH_PAIR, POP_R9 } },		// r9
	{ { PUSH_PAIR, PUSH_R10 }, { PUSH_PAIR, POP_R10 } },	// r10
	{ { PUSH_PAIR, PUSH_R11 }, { PUSH_PAIR, POP_R11 } },	// r11
	{ { PUSH_PAIR, PUSH_R12 }, { PUSH_PAIR, POP_R12 } },	// r12
	{ { PUSH_PAIR, PUSH_R13 }, { PUSH_PAIR, POP_R13 } },	// r13
	{ { PUSH_PAIR, PUSH_R14 }, { PUSH_PAIR, POP_R14 } },	// r14
	{ { PUSH_PAIR, PUSH_R15 }, { PUSH_PAIR, POP_R15 } },	// r15
};

struct section {
	const char* m_name;
	uint32_t m_address;
	uint32_t m_size;
	uint32_t m_raw;

	section()
		: m_name(nullptr), m_address(0), m_size(0), m_raw(0)
	{}

	section(const char* a, uint32_t b, uint32_t c, uint32_t d)
		: m_name(a), m_address(b), m_size(c), m_raw(d)
	{}
};

int main(int argc, char* argv[]) {
	if (argc == 2) {
		std::ifstream input(argv[1], std::ios::binary);
		if (input.good()) {
			input.unsetf(std::ios::skipws);

			// calculate size from stream by placing the position at the end and getting the offset
			input.seekg(0, std::ios::end);
			std::streampos file_size = input.tellg();
			input.seekg(0, std::ios::beg);

			// if file size > size of pe header
			if (file_size > 0x1000) {
				std::vector<uint8_t> header_bytes(0x1000);
				
				// read the pe header
				input.read((char*)header_bytes.data(), header_bytes.size());

				PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)header_bytes.data();
				PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(header_bytes.data() + dos->e_lfanew);

				section text_section;

				do {
					// find the text section and cache the info needed
					PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)(nt + 1);
					for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; i++) {
						if (!strcmp((char*)section_header->Name, ".text")) {
							text_section = { (const char*)section_header->Name, section_header->VirtualAddress, section_header->Misc.VirtualSize, section_header->PointerToRawData };
							break;
						}

						section_header++;
					}
				} while (false);

				// if the text section was found
				if (text_section.m_name) {
					// set the position to the start of the text section
					input.seekg(text_section.m_raw, std::ios::beg);

					// read the text section
					std::vector<uint8_t> file_bytes(text_section.m_size);
					input.read((char*)file_bytes.data(), file_bytes.size());

					// cache the locations for the fixup script
					std::vector<uint64_t> relative_locations;

					// iterate thru each byte and check for "obfuscation"
					for (std::size_t i = 0; i < text_section.m_size; i++) {
						// if it's a simple one-byte push OR a two-byte push
						if (((file_bytes[i] >= PUSH_RAX && file_bytes[i] <= PUSH_RDI) && file_bytes[i + 1] == PUSHFQ) || (file_bytes[i] == PUSH_PAIR && file_bytes[i + 2] == PUSHFQ)) {
							std::size_t jmp_index = 0xFFFF;
							
							// attempt to find a jmp near instruction
							for (std::size_t j = 0; j < 0x10; j++) {
								if (file_bytes[i + j] == JMP_NEAR) {
									jmp_index = j;
									break;
								}
							}

							if (jmp_index < 0xFFFF) {
								// if it's a two-byte push
								if (file_bytes[i] == PUSH_PAIR) {
									// TODO: there isn't many of these (100 max), i'll get around to optimizing it soon
								} else {
									// loop thru the possible instruction pairs
									for (auto pairs : push_pops) {
										if (pairs.first.first == file_bytes[i]) {
											uint32_t jmp_size = file_bytes[i + jmp_index + 1] + 2; // add on the size of the instruction (2)

											// if the size is in our limits
											if (jmp_size < MAX_JMP_SIZE_DETECTION) {
												if (file_bytes[i + jmp_index + jmp_size] == pairs.second.first) {
													uint32_t junk_size = 0;
													bool break_out = false;

													// sanity check to make sure there's a popfq
													for (std::size_t j = 0; j < 0x20; j++) {
														if (file_bytes[i + jmp_index + 2 + jmp_size + j] == POPFQ && file_bytes[i + jmp_index + 2 + jmp_size + j + 1] == pairs.second.first) {
															// remove the setup
															for (std::size_t k = i; k < i + jmp_index; k++)
																file_bytes[k] = 0x90;

															// remove the junk
															for (std::size_t k = i + jmp_index + 2; k < i + jmp_index + 2 + jmp_size + j + 2; k++)
																file_bytes[k] = 0x90;

															relative_locations.push_back(i + jmp_index);
															break_out = true;
															break;
														}
													}

													if (break_out)
														break;
												}
											}
										}
									}
								}
							}
						} else {
							// if it's a push that's more than one-byte
							// TODO: there isn't many of these (100 max), i'll get around to optimizing it soon
						}
					}

					// if obfuscated code was found
					if (!relative_locations.empty()) {
						// create a copy of the input to apply the patches to
						std::ofstream output(std::string(argv[1]) + ".fixed", std::ios::binary);

						// seek the start of the original
						input.seekg(0, std::ios::beg);

						// write the original
						output << input.rdbuf();

						// seek the start of the text section
						output.seekp(text_section.m_raw, std::ios::beg);

						// write the new text section
						output.write((const char*)file_bytes.data(), file_bytes.size());

						// close the file handle
						output.close();

						// TODO: create .idc
					}
				}

				// close the file handle
				input.close();
			}
		}
	}
	
	system("pause");
	return 0;
}