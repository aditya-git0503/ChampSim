#ifndef WVCRP_H
#define WVCRP_H

#include "cache.h"
#include "modules.h"
#include <cstddef>
#include <cstdint>
#include <vector>

// version 4, 27 apr

/**
 * Optimized WVCRP (Weighted Value-based Cache Replacement Policy)
 * Uses 1-byte metadata structure:
 * - Bits 7-6: 2-bit RRPV (0-3)
 * - Bits 5-3: 3-bit saturating frequency (0-7)
 * - Bits 2-1: 2-bit CPU ID (0-3)
 * - Bit 0: 1-bit reused flag
 */
class wvcrp : public champsim::modules::replacement
{
private:
    // Compact 1-byte metadata per cache block
    std::vector<std::vector<uint8_t>> metadata;
    std::vector<long> next_tiebreak_way;
    long NUM_SET;
    long NUM_WAY;

    // SHIP-style sampler entry (external state, does not change per-line metadata size)
    class sampler_entry {
    public:
        bool valid = false;
        bool reused = false;
        champsim::address line_addr{};
        champsim::address fill_ip{};
        uint64_t last_used = 0;
    };

    std::vector<long> sampled_sets;
    std::vector<sampler_entry> sampler;
    std::vector<std::vector<uint8_t>> shct;
    uint64_t sampler_access_counter = 0;
    uint64_t replacement_event_counter = 0;

    // Metadata field extraction and manipulation
    static constexpr uint8_t RRPV_MASK = 0x03;      // Bits 7-6 (2 bits)
    static constexpr uint8_t FREQ_MASK = 0x07;      // Bits 5-3 (3 bits)
    static constexpr uint8_t CPU_MASK = 0x03;       // Bits 2-1 (2 bits)
    static constexpr uint8_t REUSED_MASK = 0x01;    // Bit 0 (1 bit)
    static constexpr int RRPV_SHIFT = 6;
    static constexpr int FREQ_SHIFT = 3;
    static constexpr int CPU_SHIFT = 1;
    static constexpr uint8_t MAX_RRPV = 3;
    static constexpr uint8_t MAX_FREQ = 7;

    // Lightweight SHIP-style predictor configuration
    static constexpr std::size_t SHCT_SIZE = 16384;
    static constexpr unsigned SHCT_PRIME = 16381;
    static constexpr uint8_t SHCT_MAX = 7;
    static constexpr std::size_t SAMPLER_SET_FACTOR = 64;
    static constexpr uint64_t SHCT_DECAY_INTERVAL = 1000000;
    static constexpr uint8_t DEAD_INSERT_THRESHOLD = SHCT_MAX;

    // Insertion and update policy knobs
    static constexpr uint8_t DEMAND_INSERT_RRPV = 2;
    static constexpr uint8_t DEAD_INSERT_RRPV = 3;
    static constexpr uint8_t WRITEBACK_INSERT_RRPV = 1;
    static constexpr uint8_t DEMAND_HIT_RRPV = 0;
    static constexpr uint8_t WRITE_HIT_RRPV = 1;

    inline uint8_t get_rrpv(uint8_t meta) const {
        return (meta >> RRPV_SHIFT) & RRPV_MASK;
    }

    inline uint8_t get_frequency(uint8_t meta) const {
        return (meta >> FREQ_SHIFT) & FREQ_MASK;
    }

    inline uint8_t get_cpu_id(uint8_t meta) const {
        return (meta >> CPU_SHIFT) & CPU_MASK;
    }

    inline uint8_t get_reused(uint8_t meta) const {
        return meta & REUSED_MASK;
    }

    inline uint8_t pack_metadata(uint8_t rrpv, uint8_t freq, uint8_t cpu_id, uint8_t reused) const {
        return ((rrpv & RRPV_MASK) << RRPV_SHIFT) |
               ((freq & FREQ_MASK) << FREQ_SHIFT) |
               ((cpu_id & CPU_MASK) << CPU_SHIFT) | 
               (reused & REUSED_MASK);
    }

public:
    // Constructor that follows the ChampSim interface
    explicit wvcrp(CACHE* cache);
    wvcrp(CACHE* cache, long sets, long ways);

    // Find victim for replacement using Algorithm 1 from the specification
    long find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, 
                     champsim::address ip, champsim::address full_addr, access_type type);

    // Cache fill replacement
    void replacement_cache_fill(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, 
                               champsim::address ip, champsim::address victim_addr, access_type type);

    // Update replacement state on cache access using Algorithm 2 from the specification
    void update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, 
                                 champsim::address ip, champsim::address victim_addr, access_type type, uint8_t hit);

private:
    std::size_t shct_index(champsim::address ip) const;
    std::size_t sampler_offset(std::size_t sampled_set_pos, long way) const;
    uint8_t ensure_victim_ready(long set);
    long select_victim_from_candidates(long set, const std::vector<long>& candidates, uint8_t requester_cpu);

    void initialize_metadata(long set, long way, uint32_t triggering_cpu, champsim::address ip, access_type type);
    void update_metadata_on_hit(uint32_t triggering_cpu, long set, long way, champsim::address ip, access_type type);

    void shct_increment(uint32_t triggering_cpu, std::size_t index);
    void shct_decrement(uint32_t triggering_cpu, std::size_t index);
    void maybe_decay_shct();
    void update_sampler(uint32_t triggering_cpu, long set, champsim::address full_addr, champsim::address ip, bool hit);
};

#endif // WVCRP_H
