"""Link-layer type definitions for PCAP and PCAPNG parsing."""

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_IP_12 = 12
LINKTYPE_RAW_IP_14 = 14
LINKTYPE_RAW_IP_101 = 101
LINKTYPE_LOOPBACK_BSD = 108
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276

LINKTYPE_NAMES: dict[int, str] = {
    LINKTYPE_NULL: "NULL/Loopback",
    LINKTYPE_ETHERNET: "Ethernet",
    LINKTYPE_RAW_IP_12: "Raw IPv4/IPv6",
    LINKTYPE_RAW_IP_14: "Raw IPv4/IPv6",
    LINKTYPE_RAW_IP_101: "Raw IP",
    LINKTYPE_LOOPBACK_BSD: "BSD Loopback",
    LINKTYPE_LINUX_SLL: "Linux Cooked (SLL)",
    LINKTYPE_LINUX_SLL2: "Linux Cooked v2 (SLL2)",
}


def is_supported_linktype(linktype: int) -> bool:
    """Check if the link-layer type can be decoded."""
    return linktype in (
        LINKTYPE_NULL,
        LINKTYPE_ETHERNET,
        LINKTYPE_RAW_IP_12,
        LINKTYPE_RAW_IP_14,
        LINKTYPE_RAW_IP_101,
        LINKTYPE_LOOPBACK_BSD,
        LINKTYPE_LINUX_SLL,
        LINKTYPE_LINUX_SLL2,
    )


def get_linktype_name(linktype: int) -> str:
    """Return human-readable name of linktype or UNKNOWN(n)."""
    return LINKTYPE_NAMES.get(linktype, f"UNKNOWN({linktype})")
