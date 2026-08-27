import pytest
from evasion.port_shuffle import (
    shuffle_ports,
    shuffle_ports_prioritized,
    generate_port_ranges,
    chunk_ports,
    anti_sequential_verify,
    PRIORITY_PORTS,
)
class TestShufflePorts:
    def test_same_elements(self):
        ports = list(range(1, 101))
        shuffled = shuffle_ports(ports)
        assert sorted(shuffled) == sorted(ports)
    def test_different_order(self):
        ports = list(range(1, 1001))
        shuffled = shuffle_ports(ports)
        assert shuffled != ports  
    def test_deterministic_with_seed(self):
        ports = list(range(1, 101))
        s1 = shuffle_ports(ports, seed=42)
        s2 = shuffle_ports(ports, seed=42)
        assert s1 == s2
    def test_different_seeds_different_order(self):
        ports = list(range(1, 101))
        s1 = shuffle_ports(ports, seed=42)
        s2 = shuffle_ports(ports, seed=99)
        assert s1 != s2
    def test_does_not_mutate_original(self):
        ports = list(range(1, 51))
        original = list(ports)
        shuffle_ports(ports)
        assert ports == original
    def test_empty_list(self):
        assert shuffle_ports([]) == []
    def test_single_element(self):
        assert shuffle_ports([80]) == [80]
class TestShufflePortsPrioritized:
    def test_priority_ports_first(self):
        ports = list(range(1, 201))
        shuffled = shuffle_ports_prioritized(ports)
        priority_in_first_50 = sum(
            1 for p in shuffled[:50] if p in PRIORITY_PORTS
        )
        priority_total = sum(1 for p in ports if p in PRIORITY_PORTS)
        assert priority_in_first_50 >= priority_total * 0.8
    def test_all_elements_present(self):
        ports = list(range(1, 101))
        shuffled = shuffle_ports_prioritized(ports)
        assert sorted(shuffled) == sorted(ports)
class TestGeneratePortRanges:
    def test_full_range(self):
        ports = generate_port_ranges(1, 100)
        assert ports == list(range(1, 101))
    def test_common_only(self):
        ports = generate_port_ranges(1, 1000, common_only=True)
        assert all(p in PRIORITY_PORTS for p in ports)
        assert len(ports) > 0
    def test_default_range(self):
        ports = generate_port_ranges()
        assert len(ports) == 65535
        assert ports[0] == 1
        assert ports[-1] == 65535
class TestChunkPorts:
    def test_chunk_size(self):
        ports = list(range(1, 101))
        chunks = chunk_ports(ports, chunk_size=25)
        assert len(chunks) == 4
        assert all(len(c) == 25 for c in chunks)
    def test_uneven_chunks(self):
        ports = list(range(1, 108))
        chunks = chunk_ports(ports, chunk_size=25)
        assert len(chunks) == 5
        assert len(chunks[-1]) == 7  
    def test_single_chunk(self):
        ports = list(range(1, 11))
        chunks = chunk_ports(ports, chunk_size=100)
        assert len(chunks) == 1
    def test_preserves_order(self):
        ports = [80, 22, 443, 3389]
        chunks = chunk_ports(ports, chunk_size=2)
        assert chunks[0] == [80, 22]
        assert chunks[1] == [443, 3389]
class TestAntiSequentialVerify:
    def test_random_order_passes(self):
        ports = shuffle_ports(list(range(1, 1001)), seed=42)
        assert anti_sequential_verify(ports, max_run=3) is True
    def test_sequential_fails(self):
        ports = list(range(1, 101))
        assert anti_sequential_verify(ports, max_run=3) is False
    def test_short_list(self):
        assert anti_sequential_verify([80]) is True
        assert anti_sequential_verify([]) is True
    def test_allowed_short_runs(self):
        ports = [10, 11, 12, 50, 51, 52, 100]
        assert anti_sequential_verify(ports, max_run=3) is True
    def test_exceeds_max_run(self):
        ports = [10, 11, 12, 13, 50]
        assert anti_sequential_verify(ports, max_run=3) is False