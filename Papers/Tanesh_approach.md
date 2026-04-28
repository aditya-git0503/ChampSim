# D-WVCRP (Conservative SHIP + SRRIP + Frequency Tie-Breaking)

This document describes the current D-WVCRP implementation in:
- replacement/wvcrp/wvcrp.h
- replacement/wvcrp/wvcrp.cc

## 1) Policy Overview

D-WVCRP is a hybrid LLC replacement policy that combines three ideas:
- SRRIP-style aging with a 2-bit RRPV (0..3)
- SHIP-style dead-block prediction with per-PC signatures (SHCT)
- WVCRP-style frequency tie-breaking among eviction candidates

Design goal:
- Avoid aggressive insertion behavior that can cause priority inversion
- Preserve SRRIP stability while still using learned dead-block hints

## 2) Metadata and Tables

Per cache block (BlockMeta):
- rrpv: re-reference prediction value, 0 (most likely reuse) to 3 (least likely)
- freq: saturating frequency counter, 0..7
- reused: whether the block was reused since fill
- fill_sig: signature (hashed PC) captured at fill time

Global/per-policy state:
- SHCT_SIZE = 16384 entries per CPU
- SHCT counter width = 3 bits (0..7)
- SHCT_PRIME = 16381 used for signature hashing modulus
- SHCT decay interval = every 1,000,000 replacement-state updates

## 3) Core Algorithm

### 3.1 Victim Selection (find_victim)

1. Find the maximum RRPV value currently present in the set.
2. If max RRPV < 3, age all blocks in the set so that at least one reaches RRPV=3.
3. Among blocks with RRPV=3, evict the block with the lowest freq.
4. SHIP feedback on eviction:
   - If the evicted block was never reused, increment SHCT for its fill signature.

This keeps SRRIP victim readiness while letting WVCRP choose the weakest candidate among equally old blocks.

### 3.2 Fill/Insertion Policy (replacement_cache_fill)

- Writeback fill: insert at RRPV=1 and mark signature as sentinel (no SHCT training)
- Demand fill:
  - If dead-predicted by SHCT (counter at max value 7): insert at RRPV=3
  - Otherwise: insert at RRPV=2

Important safety rule in v5:
- No insertion at RRPV=0. Only hits can move a line to MRU.

### 3.3 Hit Update Policy (update_replacement_state)

Demand hit:
- Set RRPV=0 (MRU)
- Increment freq (saturating)
- If this is first reuse since fill, mark reused=true and decrement SHCT for fill signature

Write hit:
- Set RRPV=1 (partial protection, not MRU)

Periodic adaptation:
- Every SHCT_DECAY_INTERVAL updates, decrement non-zero SHCT counters.

## 4) Why v5 Exists

Earlier versions inserted some demand lines too aggressively at RRPV=0.
That can create priority inversion:
- Too many blocks stay at low RRPV values
- Victim creation requires frequent set-wide aging
- Effective replacement quality degrades over long runs

v5 fixes this by keeping insertion conservative (RRPV=2 default, RRPV=3 only for strong dead prediction).

## 5) Build and Run

From repository root:

```bash
./config.sh champsim_config.json
make clean
make

./bin/champsim \
  --warmup-instructions 200000000 \
  --simulation-instructions 500000000 \
  benckmark/401.bzip2-226B.champsimtrace.xz
```

## 6) Configuration

Ensure LLC replacement is set to wvcrp in champsim_config.json:

```json
{
  "LLC": {
    "replacement": "wvcrp"
  }
}
```

## 7) Metrics to Compare Against Baselines

Primary metrics:
- LLC TOTAL MISS
- LLC LOAD/RFO/WRITE breakdown
- IPC

If WVCRP underperforms LRU in a long run, inspect:
- WRITE miss inflation at LLC
- Whether SHCT training becomes too strong or too weak for the workload

## 8) Current Tuning Knobs

In replacement/wvcrp/wvcrp.h:
- SHCT_DECAY_INTERVAL
- SHCT_SIZE and SHCT_BITS
- MAX_FREQ
- maxRRPV (fixed at 3 for current SRRIP-like behavior)

In replacement/wvcrp/wvcrp.cc:
- Write fill/hit RRPV values
- Dead-prediction threshold (currently SHCT counter must be 7)

## 9) Notes

- This implementation is LLC-focused and assumes standard ChampSim replacement callbacks.
- The policy favors stability and robustness over aggressive early prediction.
- For final claims, use multiple traces and long simulation windows.

## 10) D-WVCRP v3: Hardware Cost Analysis and Real-World Implementation

This section captures the hardware feasibility view for the original D-WVCRP v3 design intent.
Important: the metadata footprint described here is also valid for the current code structure in this folder.

### 10.1 Per-Block Metadata Cost

Per-block logical storage requirements:
- RRPV: 2 bits
- Frequency counter: 3 bits (0..7)
- Reuse flag: 1 bit
- Fill signature: 14 bits (log2(16384))

Total D-WVCRP bits per block:
- 2 + 3 + 1 + 14 = 20 bits

Comparison (16-way LLC):

| Policy | Bits per block | Meaning |
|---|---:|---|
| LRU | 4 | Recency position (log2(16)) |
| SRRIP | 2 | RRPV only |
| D-WVCRP | 20 | RRPV + freq + reused + fill_sig |

Example overhead for 2 MiB LLC, 64 B line, 16-way:
- Number of lines = 2 MiB / 64 B = 32768
- Metadata bits = 32768 x 20 = 655360 bits = 81920 B = 80 KiB
- Relative to 2 MiB data array: about 3.9%

### 10.2 SHCT Table Cost

Per core SHCT in this implementation:
- Entries = 16384
- Counter width = 3 bits
- Storage = 16384 x 3 = 49152 bits = 6144 B = 6 KiB

### 10.3 Total Hardware Budget

Single-core, 2 MiB LLC:
- Per-block metadata: 80 KiB
- SHCT: 6 KiB
- Total policy storage: 86 KiB
- Relative overhead vs 2 MiB data array: about 4.2%

Quad-core, shared 2 MiB LLC with per-core SHCT:
- Per-block metadata: 80 KiB
- SHCT: 4 x 6 KiB = 24 KiB
- Total policy storage: 104 KiB
- Relative overhead vs 2 MiB data array: about 5.1%

### 10.4 Logic and Latency Cost

Critical operation on LLC miss: victim selection in find_victim.

Logical steps:
1. Reduce max RRPV over all ways in the set.
2. Compute required aging bump and saturate-add to each way.
3. Compare only RRPV=3 candidates and pick minimum freq.
4. SHCT update on eviction (single counter increment).

Why timing is practical:
- Set-local operations over small associativity (for example 16 ways).
- Integer comparators and adders only.
- No floating-point operations, multipliers, trace replay, or OPTgen-style emulation.

Compared with heavier learning-based policies, D-WVCRP control logic is closer to SRRIP/SHIP complexity.

### 10.5 Real-World RTL Mapping (Verilog-Style)

#### 10.5.1 Per-Block Storage Register

```verilog
typedef struct packed {
  logic [1:0] rrpv;      // 2 bits
  logic [2:0] freq;      // 3 bits
  logic       reused;    // 1 bit
  logic [13:0] fill_sig; // 14 bits
} block_meta_t;
```

#### 10.5.2 Victim Selection Circuit

```verilog
// Pseudocode-style RTL
max_rrpv = max(rrpv_way[0:WAYS-1]);
bump = 2'd3 - max_rrpv;

for each way:
  aged_rrpv[way] = sat_add(rrpv_way[way], bump, 2'd3);

victim = argmin(freq_way[way]) among ways where aged_rrpv[way] == 2'd3;
```

#### 10.5.3 SHCT Table (SRAM)

```verilog
// 16K x 3b per core
logic [2:0] shct [0:16383];

if (evicted_never_reused) shct[evicted_sig] <= sat_inc(shct[evicted_sig]);
if (first_reuse_hit)      shct[fill_sig]    <= sat_dec(shct[fill_sig]);
```

#### 10.5.4 Graduated Prediction Logic

```verilog
dead_pred = (shct[sig] == 3'b111);
insert_rrpv = dead_pred ? 2'd3 : 2'd2;
```

This decision logic is a simple compare plus mux.

### 10.6 Power Consumption Estimate

Qualitative estimate for added replacement-policy power:
- Dynamic power increase is primarily from extra metadata read/write and SHCT accesses.
- Area and leakage growth are dominated by small SRAM/register additions (tens of KiB scale).
- For typical LLC designs, this is expected to be modest and materially below the cost of complex predictor families that maintain larger history structures.

Practical expectation:
- Small single-digit percentage increase in replacement-control power domain.
- Minimal impact on total chip power relative to core and DRAM subsystems.

### 10.7 Hardware Feasibility Summary

D-WVCRP is hardware-feasible for production-style LLC pipelines:
- Storage footprint is moderate (roughly 86 KiB for the single-core 2 MiB example).
- Logic consists of simple integer datapath operations.
- Critical-path pressure is similar to SRRIP/SHIP-class policies.

### 10.8 Real-World Deployment Path

Suggested deployment sequence:
1. Start with a baseline SRRIP/SHIP implementation in RTL.
2. Add frequency counter and minimum-frequency tie-break among RRPV=3 candidates.
3. Add per-core SHCT and first-reuse training feedback.
4. Validate timing closure at target frequency.
5. Run power and area signoff, then tune SHCT size and decay interval if needed.

Bottom line:
D-WVCRP is practical for silicon deployment, with manageable storage and control complexity while retaining a straightforward LLC integration path.
