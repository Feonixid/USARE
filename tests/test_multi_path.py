import pytest
from evasion.multi_path_dispersion import (
    SourceNode,
    SourceType,
    DispersionConfig,
    ProxyChainManager,
    get_dispersion_stats,
)


def test_source_node_creation():
    node = SourceNode(
        id="proxy-1",
        source_type=SourceType.PROXY,
        ip_address="10.0.0.1",
        port=8080,
        country="US",
        provider="CloudProxy",
    )
    assert node.id == "proxy-1"
    assert node.source_type == SourceType.PROXY
    assert node.health_score == 1.0
    assert node.active is True


def test_proxy_chain_manager_add_and_select():
    config = DispersionConfig(load_balance_strategy="heat_aware")
    manager = ProxyChainManager(config)

    node1 = SourceNode(
        id="node-1",
        source_type=SourceType.VPN,
        ip_address="10.0.0.1",
        port=1194,
        health_score=0.9,
        current_heat=0.1,
    )
    node2 = SourceNode(
        id="node-2",
        source_type=SourceType.PROXY,
        ip_address="10.0.0.2",
        port=8080,
        health_score=0.9,
        current_heat=0.7,
    )
    manager.add_source_node(node1)
    manager.add_source_node(node2)

    assert len(manager.source_nodes) == 2

    # In heat-aware mode, node1 (heat=0.1) should be preferred over node2 (heat=0.7)
    selected = manager.select_source_node("192.168.1.1", 80)
    assert selected is not None
    assert selected.id == "node-1"


def test_proxy_chain_manager_statistics():
    config = DispersionConfig()
    manager = ProxyChainManager(config)
    manager.add_source_node(
        SourceNode(
            id="node-us",
            source_type=SourceType.PROXY,
            ip_address="1.1.1.1",
            port=8080,
            country="US",
            provider="AWS",
        )
    )
    manager.add_source_node(
        SourceNode(
            id="node-eu",
            source_type=SourceType.TOR,
            ip_address="2.2.2.2",
            port=9050,
            country="DE",
            provider="Hetzner",
        )
    )

    stats = manager.get_statistics()
    assert stats["total_nodes"] == 2
    assert stats["active_nodes"] == 2
    assert stats["geographic_diversity"] == 2
    assert stats["nodes_by_type"]["proxy"] == 1
    assert stats["nodes_by_type"]["tor"] == 1
