#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <unordered_map>
#include <sstream>

// rebase to this when you load the fixed exe in IDA
#define BASE 0x140000000

enum EPushPop {
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
};

std::vector<std::pair<std::pair<uint8_t, uint8_t>, std::pair<uint8_t, uint8_t>>> push_pops = {
    { { PUSH_RAX, PUSH_NONE }, { POP_RAX, PUSH_NONE } }, // rax
    { { PUSH_RCX, PUSH_NONE }, { POP_RCX, PUSH_NONE } }, // rcx
    { { PUSH_RDX, PUSH_NONE }, { POP_RDX, PUSH_NONE } }, // rdx
    { { PUSH_RBX, PUSH_NONE }, { POP_RBX, PUSH_NONE } }, // rbx
    { { PUSH_RSP, PUSH_NONE }, { POP_RSP, PUSH_NONE } }, // rsp
    { { PUSH_RBP, PUSH_NONE }, { POP_RBP, PUSH_NONE } }, // rbp
    { { PUSH_RSI, PUSH_NONE }, { POP_RSI, PUSH_NONE } }, // rsi
    { { PUSH_RDI, PUSH_NONE }, { POP_RDI, PUSH_NONE } }, // rdi
    { { PUSH_PAIR, PUSH_R8 }, { PUSH_PAIR, POP_R8 } }, // r8
    { { PUSH_PAIR, PUSH_R9 }, { PUSH_PAIR, POP_R9 } }, // r9
    { { PUSH_PAIR, PUSH_R10 }, { PUSH_PAIR, POP_R10 } }, // r10
    { { PUSH_PAIR, PUSH_R11 }, { PUSH_PAIR, POP_R11 } }, // r11
    { { PUSH_PAIR, PUSH_R12 }, { PUSH_PAIR, POP_R12 } }, // r12
    { { PUSH_PAIR, PUSH_R13 }, { PUSH_PAIR, POP_R13 } }, // r13
    { { PUSH_PAIR, PUSH_R14 }, { PUSH_PAIR, POP_R14 } }, // r14
    { { PUSH_PAIR, PUSH_R15 }, { PUSH_PAIR, POP_R15 } }, // r15
};

struct Header {
    uint32_t m_address;
    uint32_t m_size;
    uint32_t m_raw;
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

            // create vector to store the file
            std::vector<uint8_t> file_bytes;
            file_bytes.reserve(file_size);

            // copy the file bytes from the stream into the vector
            file_bytes.insert(begin(file_bytes), std::istream_iterator<uint8_t>(input), std::istream_iterator<uint8_t>());

            input.close();

            // parse out the headers from the file
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)file_bytes.data();
            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(file_bytes.data() + dos->e_lfanew);

            // create vector to store the headers
            std::vector<std::pair<std::string, Header>> headers;

            PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)(nt + 1);
            for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                headers.push_back({ (char*)section_header->Name, { section_header->VirtualAddress, section_header->Misc.VirtualSize, section_header->PointerToRawData } });
                section_header++;
            }

            // for now we only need .text for code flow deobfuscation, so find the text section and start the iteration
            auto iteration = std::find_if(begin(headers), end(headers), [](const std::unordered_map<std::string, Header>::value_type& element) {
                return !element.first.compare(".text");
            });

            // if it found the .text section
            if (iteration != end(headers)) {
                // create vector to cache the locations for the fixup script
                std::vector<uint64_t> relative_locations;

                uint32_t total_count = 0;
                uint32_t total_count_potential_bad = 0;

                for (std::size_t i = iteration->second.m_raw; i < iteration->second.m_size + iteration->second.m_raw; i++) {
                    // if its a push instruction
                    if (file_bytes[i] == PUSH_PAIR || (file_bytes[i] >= PUSH_RAX && file_bytes[i] <= PUSH_RDI)) {
                        int jmp_index = -1;

                        // attempt to find a jmp
                        for (std::size_t j = 0; j <= 10; j++) {
                            if (file_bytes[i + 1 + j] == 0xEB) {
                                jmp_index = j + 1;
                                break;
                            }
                        }

                        // if a jmp was (hopefully) found
                        if (jmp_index != -1) {
                            // if the push instruction has two bytes for its opcode length
                            if (file_bytes[i] == PUSH_PAIR) {
                                if (file_bytes[i + 1] >= PUSH_RAX && file_bytes[i + 1] <= PUSH_RDI) {
                                    for (auto pairs : push_pops) {
                                        if (pairs.first.second == file_bytes[i + 1]) {
                                            uint32_t jmp_size = file_bytes[i + jmp_index + 1] + 2;
                                            if (file_bytes[i + jmp_index + jmp_size] == pairs.second.first && file_bytes[i + jmp_index + jmp_size + 1] == pairs.second.second) {
                                                total_count++;

                                                // remove the setup intructions (push)
                                                for (std::size_t k = i; k < i + jmp_index; k++) {
                                                    file_bytes[k] = 0x90;
                                                }

                                                // remove the de-setup(?) instructions (pop)
                                                for (std::size_t k = i + jmp_index + 2; k < i + jmp_index + 1 + jmp_size; k++) {
                                                    file_bytes[k] = 0x90;
                                                }

                                                relative_locations.push_back(BASE + i + jmp_index + 0xA00);
                                                relative_locations.push_back(BASE + i + jmp_index + jmp_size + 0xA00);

                                                break;
                                            }
                                        }
                                    }
                                }
                            } else {
                                for (auto pairs : push_pops) {
                                    if (pairs.first.first == file_bytes[i]) {
                                        uint32_t jmp_size = file_bytes[i + jmp_index + 1] + 2;

                                        // sometimes there can be false positives, checking the jmp size helps with that (never usually goes above this) 
                                        if (jmp_size < 80) {
                                            if (file_bytes[i + jmp_index + jmp_size] == pairs.second.first) {
                                                total_count++;

                                                // remove the setup intructions (push)
                                                for (std::size_t k = i; k < i + jmp_index; k++) {
                                                    file_bytes[k] = 0x90;
                                                }

                                                // remove the de-setup(?) instructions (pop)
                                                for (std::size_t k = i + jmp_index + 2; k < i + jmp_index + 1 + jmp_size; k++) {
                                                    file_bytes[k] = 0x90;
                                                }

                                                if (jmp_size > 70) total_count_potential_bad++;

                                                relative_locations.push_back(BASE + i + jmp_index + 0xA00);
                                                relative_locations.push_back(BASE + i + jmp_index + jmp_size + 0xA00);

                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if (total_count > 0) {
                    std::cout << "[*] Found " << total_count << " blocks of code flow obfuscation!" << std::endl;

                    if (total_count_potential_bad > 0) {
                        std::cout << "[*] Found " << total_count_potential_bad << " potentially bad blocks of code flow obfuscation!" << std::endl;
                    }

                    std::string file_name = std::string(argv[1]);
                    std::ofstream output(file_name + ".fixed", std::ios::binary);
                    if (output.good()) {
                        output.write((const char*)&file_bytes[0], file_bytes.size());
                        output.close();

                        std::cout << "[*] Fixed executable written!" << std::endl;

                        output = std::ofstream(file_name.substr(0, file_name.find_last_of("\\/")) + "\\loc_fix.idc");
                        if (output.good()) {
                            output << "#include <idc.idc>" << std::endl;
                            output << "static main() {" << std::endl;

                            for (uint64_t location : relative_locations) {
                                std::stringstream stream;
                                stream << "0x" << std::hex << location;

                                output << "\tMakeUnkn(" << stream.str() << ", 1); MakeCode(" << stream.str() << ");" << std::endl;
                            }

                            output << "}";
                            output.close();

                            std::cout << "[*] Finished!" << std::endl;
                        } else {
                            std::cout << "[!] Failed writing to output idc file \"" << file_name.substr(0, file_name.find_last_of("\\/")) + "\\loc_fix.idc" << "\"!" << std::endl;
                        }
                    } else {
                        std::cout << "[!] Failed writing to output file \"" << argv[1] << ".fixed\"!" << std::endl;
                    }
                } else {
                    std::cout << "[!] Failed finding obfuscation in \"" << argv[1] << "\"!" << std::endl;
                }
            } else {
                std::cout << "[!] Failed finding text section in \"" << argv[1] << "\"!" << std::endl;
            }
        } else {
            std::cout << "[!] Failed opening input file \"" << argv[1] << "\"!" << std::endl;
        }
    }

    return 0;
}
