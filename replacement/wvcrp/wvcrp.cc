#include "wvcrp.h"

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <limits>
#include <random>

#include "champsim.h"
#include "msl/bits.h"

// version 4, 27 apr

wvcrp::wvcrp(CACHE* cache) : wvcrp(cache, cache->NUM_SET, cache->NUM_WAY) {}

wvcrp::wvcrp(CACHE* cache, long sets, long ways)
  : replacement(cache), metadata(static_cast<std::size_t>(sets), std::vector<uint8_t>(static_cast<std::size_t>(ways), 0)),
    next_tiebreak_way(static_cast<std::size_t>(sets), 0), NUM_SET(sets), NUM_WAY(ways)
{
  for (long set = 0; set < NUM_SET; ++set) {
    for (long way = 0; way < NUM_WAY; ++way)
      metadata.at(static_cast<std::size_t>(set)).at(static_cast<std::size_t>(way)) = pack_metadata(MAX_RRPV, 0, 0, 0);
  }

  if (!ENABLE_SHIP_PREDICTOR)
    return;

  std::size_t target_sampled_sets =
      std::min<std::size_t>(static_cast<std::size_t>(NUM_SET), SAMPLER_SET_FACTOR * static_cast<std::size_t>(NUM_CPUS));
  sampled_sets.reserve(target_sampled_sets);

  if (target_sampled_sets > 0) {
    std::vector<uint8_t> seen(static_cast<std::size_t>(NUM_SET), 0);
    std::knuth_b rng{1};
    while (sampled_sets.size() < target_sampled_sets) {
      long candidate = static_cast<long>(rng() % static_cast<unsigned>(NUM_SET));
      auto idx = static_cast<std::size_t>(candidate);
      if (seen.at(idx) == 0) {
        seen.at(idx) = 1;
        sampled_sets.push_back(candidate);
      }
    }
  }

  std::sort(sampled_sets.begin(), sampled_sets.end());
  sampler.resize(sampled_sets.size() * static_cast<std::size_t>(NUM_WAY));
  shct.assign(NUM_CPUS, std::vector<uint8_t>(SHCT_SIZE, 0));
}

std::size_t wvcrp::shct_index(champsim::address ip) const
{
  using namespace champsim::data::data_literals;
  return ip.slice_lower<32_b>().to<std::size_t>() % SHCT_PRIME;
}

std::size_t wvcrp::sampler_offset(std::size_t sampled_set_pos, long way) const
{
  return sampled_set_pos * static_cast<std::size_t>(NUM_WAY) + static_cast<std::size_t>(way);
}

uint8_t wvcrp::ensure_victim_ready(long set)
{
  auto& set_metadata = metadata.at(static_cast<std::size_t>(set));

  uint8_t max_rrpv = 0;
  for (long way = 0; way < NUM_WAY; ++way) {
    uint8_t rrpv = get_rrpv(set_metadata.at(static_cast<std::size_t>(way)));
    if (rrpv > max_rrpv)
      max_rrpv = rrpv;
  }

  if (max_rrpv < MAX_RRPV) {
    uint8_t bump = static_cast<uint8_t>(MAX_RRPV - max_rrpv);
    for (long way = 0; way < NUM_WAY; ++way) {
      uint8_t meta = set_metadata.at(static_cast<std::size_t>(way));
      uint8_t aged_rrpv = std::min<uint8_t>(MAX_RRPV, static_cast<uint8_t>(get_rrpv(meta) + bump));
      set_metadata.at(static_cast<std::size_t>(way)) = pack_metadata(aged_rrpv, get_frequency(meta), get_cpu_id(meta), get_reused(meta));
    }

    max_rrpv = MAX_RRPV;
  }

  return max_rrpv;
}

long wvcrp::select_victim_from_candidates(long set, const std::vector<long>& candidates, uint8_t requester_cpu)
{
  if (candidates.empty())
    return 0;

  auto& set_metadata = metadata.at(static_cast<std::size_t>(set));
  std::vector<long> active = candidates;

  uint8_t min_freq = MAX_FREQ;
  for (long way : active) {
    uint8_t freq = get_frequency(set_metadata.at(static_cast<std::size_t>(way)));
    if (freq < min_freq)
      min_freq = freq;
  }

  std::vector<long> freq_best;
  for (long way : active) {
    uint8_t freq = get_frequency(set_metadata.at(static_cast<std::size_t>(way)));
    if (freq == min_freq)
      freq_best.push_back(way);
  }
  active.swap(freq_best);

  std::vector<long> non_reused;
  for (long way : active) {
    if (get_reused(set_metadata.at(static_cast<std::size_t>(way))) == 0)
      non_reused.push_back(way);
  }
  if (!non_reused.empty())
    active.swap(non_reused);

  std::vector<long> foreign_owner;
  for (long way : active) {
    if (get_cpu_id(set_metadata.at(static_cast<std::size_t>(way))) != requester_cpu)
      foreign_owner.push_back(way);
  }
  if (!foreign_owner.empty())
    active.swap(foreign_owner);

  long victim = active.front();
  long start = next_tiebreak_way.at(static_cast<std::size_t>(set));
  for (long offset = 0; offset < NUM_WAY; ++offset) {
    long probe = (start + offset) % NUM_WAY;
    if (std::find(active.begin(), active.end(), probe) != active.end()) {
      victim = probe;
      break;
    }
  }

  next_tiebreak_way.at(static_cast<std::size_t>(set)) = (victim + 1) % NUM_WAY;
  return victim;
}

long wvcrp::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip,
                        champsim::address full_addr, access_type type)
{
  (void)instr_id;
  (void)ip;
  (void)full_addr;
  (void)type;

  if (set < 0 || set >= NUM_SET)
    return 0;

  for (long way = 0; way < NUM_WAY; ++way) {
    if (!current_set[way].valid)
      return way;
  }

  uint8_t ready_rrpv = ensure_victim_ready(set);
  std::vector<long> candidates;
  uint8_t requester_cpu = static_cast<uint8_t>(triggering_cpu & CPU_MASK);
  auto& set_metadata = metadata.at(static_cast<std::size_t>(set));

  for (long way = 0; way < NUM_WAY; ++way) {
    uint8_t meta = set_metadata.at(static_cast<std::size_t>(way));
    if (get_rrpv(meta) == ready_rrpv)
      candidates.push_back(way);
  }

  if (candidates.empty()) {
    for (long way = 0; way < NUM_WAY; ++way)
      candidates.push_back(way);
  }

  return select_victim_from_candidates(set, candidates, requester_cpu);
}

void wvcrp::replacement_cache_fill(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip,
                                   champsim::address victim_addr, access_type type)
{
  (void)victim_addr;

  if (set < 0 || set >= NUM_SET || way < 0 || way >= NUM_WAY)
    return;

  initialize_metadata(set, way, triggering_cpu, ip, type);
  if (ENABLE_SHIP_PREDICTOR && access_type{type} != access_type::WRITE) {
    update_sampler(triggering_cpu, set, full_addr, ip, false);
    maybe_decay_shct();
  }
}

void wvcrp::update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip,
                                     champsim::address victim_addr, access_type type, uint8_t hit)
{
  (void)victim_addr;

  // ChampSim may call this on misses with way == NUM_WAY; ignore those updates.
  if (!hit)
    return;

  if (set < 0 || set >= NUM_SET || way < 0 || way >= NUM_WAY)
    return;

  update_metadata_on_hit(triggering_cpu, set, way, ip, type);
  if (ENABLE_SHIP_PREDICTOR) {
    update_sampler(triggering_cpu, set, full_addr, ip, true);
    maybe_decay_shct();
  }
}

void wvcrp::initialize_metadata(long set, long way, uint32_t triggering_cpu, champsim::address ip, access_type type)
{
  auto& meta = metadata.at(static_cast<std::size_t>(set)).at(static_cast<std::size_t>(way));
  uint8_t cpu_bits = static_cast<uint8_t>(triggering_cpu & CPU_MASK);

  uint8_t insertion_rrpv = DEMAND_INSERT_RRPV;
  uint8_t initial_freq = 1;

  if (access_type{type} == access_type::WRITE) {
    insertion_rrpv = WRITEBACK_INSERT_RRPV;
    initial_freq = 0;
  } else if (ENABLE_SHIP_PREDICTOR && !shct.empty()) {
    auto cpu_index = static_cast<std::size_t>(triggering_cpu) % shct.size();
    uint8_t predictor = shct.at(cpu_index).at(shct_index(ip));
    if (predictor >= DEAD_INSERT_THRESHOLD)
      insertion_rrpv = DEAD_INSERT_RRPV;
  }

  meta = pack_metadata(insertion_rrpv, initial_freq, cpu_bits, 0);
}

void wvcrp::update_metadata_on_hit(uint32_t triggering_cpu, long set, long way, champsim::address ip, access_type type)
{
  auto& meta = metadata.at(static_cast<std::size_t>(set)).at(static_cast<std::size_t>(way));

  uint8_t rrpv = get_rrpv(meta);
  uint8_t freq = get_frequency(meta);
  uint8_t reused = get_reused(meta);
  uint8_t cpu_bits = static_cast<uint8_t>(triggering_cpu & CPU_MASK);

  if (access_type{type} == access_type::WRITE) {
    if (rrpv > WRITE_HIT_RRPV)
      rrpv = WRITE_HIT_RRPV;

    if (freq < MAX_FREQ && (freq & 0x1) == 0)
      ++freq;
  } else {
    rrpv = DEMAND_HIT_RRPV;
    if (freq < MAX_FREQ)
      ++freq;

    if (reused == 0) {
      reused = 1;
      if (ENABLE_SHIP_PREDICTOR)
        shct_decrement(triggering_cpu, shct_index(ip));
    }
  }

  meta = pack_metadata(rrpv, freq, cpu_bits, reused);
}

void wvcrp::shct_increment(uint32_t triggering_cpu, std::size_t index)
{
  if (shct.empty())
    return;

  auto cpu_index = static_cast<std::size_t>(triggering_cpu) % shct.size();
  auto& value = shct.at(cpu_index).at(index);
  if (value < SHCT_MAX)
    ++value;
}

void wvcrp::shct_decrement(uint32_t triggering_cpu, std::size_t index)
{
  if (shct.empty())
    return;

  auto cpu_index = static_cast<std::size_t>(triggering_cpu) % shct.size();
  auto& value = shct.at(cpu_index).at(index);
  if (value > 0)
    --value;
}

void wvcrp::maybe_decay_shct()
{
  if (!ENABLE_SHIP_PREDICTOR)
    return;

  ++replacement_event_counter;
  if (replacement_event_counter % SHCT_DECAY_INTERVAL != 0)
    return;

  for (auto& table : shct) {
    for (auto& value : table) {
      if (value > 0)
        --value;
    }
  }
}

void wvcrp::update_sampler(uint32_t triggering_cpu, long set, champsim::address full_addr, champsim::address ip, bool hit)
{
  if (!ENABLE_SHIP_PREDICTOR)
    return;

  if (sampled_sets.empty())
    return;

  auto sampled_it = std::lower_bound(sampled_sets.begin(), sampled_sets.end(), set);
  if (sampled_it == sampled_sets.end() || *sampled_it != set)
    return;

  std::size_t sampled_set_pos = static_cast<std::size_t>(std::distance(sampled_sets.begin(), sampled_it));

  auto begin = std::next(sampler.begin(), static_cast<long>(sampler_offset(sampled_set_pos, 0)));
  auto end = std::next(begin, NUM_WAY);

  using namespace champsim::data::data_literals;
  auto match = std::find_if(begin, end, [addr = full_addr](const sampler_entry& entry) {
    return entry.valid && entry.line_addr.slice_upper<6_b>() == addr.slice_upper<6_b>();
  });

  if (hit && match != end) {
    if (!match->reused)
      shct_decrement(match->cpu_id, shct_index(match->fill_ip));

    match->reused = true;
    match->last_used = sampler_access_counter++;
    return;
  }

  if (match == end) {
    match = std::min_element(begin, end, [](const sampler_entry& lhs, const sampler_entry& rhs) {
      return lhs.last_used < rhs.last_used;
    });
  }

  if (match == end)
    return;

  if (match->valid && !match->reused)
    shct_increment(match->cpu_id, shct_index(match->fill_ip));

  match->valid = true;
  match->line_addr = full_addr;
  match->fill_ip = ip;
  match->cpu_id = triggering_cpu;
  match->reused = hit;
  match->last_used = sampler_access_counter++;
}
