#pragma once

#include "psprecomp/elf32.hpp"

#include <cstdint>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace psprecomp {

struct ExecutableRange {
    std::uint32_t start{};
    std::uint32_t end{};
};

struct FunctionAnalysis {
    std::uint32_t entry{};
    std::set<std::uint32_t> labels;       // all decoded instruction addresses (delay slots excluded)
    std::set<std::uint32_t> entry_labels; // function entry and basic-block/return continuations
    std::set<std::uint32_t> direct_calls;
    std::set<std::uint32_t> indirect_call_sites;
    std::size_t basic_block_count{};
    std::size_t unsupported_instruction_count{};
    bool truncated{};
};

struct ProgramAnalysis {
    std::vector<ExecutableRange> executable_ranges;
    std::map<std::uint32_t, std::string> seeds;
    std::vector<FunctionAnalysis> functions;
    std::set<std::uint32_t> covered_labels;
    std::set<std::uint32_t> covered_entry_labels;
    std::size_t overlapping_label_count{};
};

// Feature test for tools that also build against older framework revisions.
#define PSPRECOMP_ANALYSIS_HINTS 1

// Knowledge about a module that the automatic analysis cannot derive on its
// own, usually exported from a disassembler (function entries found by its
// analyzers, jump tables it resolved). Every address is a runtime address.
struct AnalysisHints {
    // When non-empty, replaces the executable ranges derived from the
    // PT_LOAD segments (a PRX's first segment also holds .rodata, so the
    // automatic ranges decode data as code).
    std::vector<ExecutableRange> code_ranges;
    // Extra function entries, address -> source tag.
    std::map<std::uint32_t, std::string> seeds;
    // Resolved `jr` sites: the targets become blocks of the function that
    // owns the jr, so they are emitted and registered as dispatcher entries.
    std::map<std::uint32_t, std::vector<std::uint32_t>> jump_tables;
};

// Reads hints from a text file, one directive per line ('#' starts a comment):
//   code <start> <end>                 executable range [start, end)
//   seed <address> [source]            function entry
//   jumptable <jr address> <target>... targets of an indirect jump
// Numbers are hexadecimal with or without 0x. Throws psprecomp::Error.
[[nodiscard]] AnalysisHints load_analysis_hints(const std::filesystem::path &path);

[[nodiscard]] bool is_executable_address(const std::vector<ExecutableRange> &ranges,
                                         std::uint32_t address) noexcept;

[[nodiscard]] ProgramAnalysis analyze_program(const Elf32Image &elf, const GuestMemory &memory, std::uint32_t load_base,
    std::size_t max_instructions_per_function = 131072u);

[[nodiscard]] ProgramAnalysis analyze_program(const Elf32Image &elf,
                                              const GuestMemory &memory,
                                              std::uint32_t load_base,
                                              const AnalysisHints &hints,
                                              std::size_t max_instructions_per_function = 131072u);

} // namespace psprecomp
