import argparse
import sys
from scapy.all import Dot11Beacon, get_if_list, sniff


def parse_args():
    parser = argparse.ArgumentParser(
        description="Test packet capture on a specific wireless interface."
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="Interface name or Npcap device string",
        default=None
    )
    return parser.parse_args()


def main():
    args = parse_args()
    iface = args.interface
    if not iface:
        interfaces = get_if_list()
        print("ERROR: Interface required.")
        if interfaces:
            print("Available interfaces:")
            for name in interfaces:
                print(f"  - {name}")
        print("\nRun: python test_interface.py -i \"<interface>\"")
        sys.exit(2)

    print(f"Testing interface: {iface}")
    print("Attempting to capture packets (this may take a few seconds)...")

    try:
        pkts = sniff(iface=iface, timeout=5, count=0)
        print("SUCCESS: Interface is accessible")
        print(f"Captured {len(pkts)} packets in 5 seconds")

        print("\nAttempting to capture 802.11 beacon frames...")
        pkts = sniff(
            iface=iface,
            timeout=3,
            lfilter=lambda p: p.haslayer(Dot11Beacon),
            store=True
        )
        print(f"Captured {len(pkts)} beacon frames")

        if len(pkts) > 0:
            print("SUCCESS: Wireless networks can be detected!")
        else:
            print("WARNING: No beacon frames captured. Possible reasons:")
            print("  1. No wireless networks in range")
            print("  2. Wi-Fi adapter does not support monitor mode on Windows")
            print("  3. Adapter is not in monitor mode (required for passive scanning)")

    except Exception as e:
        print(f"ERROR: {e}")
        print("\nThis error indicates why scanning is not working.")
        sys.exit(1)


if __name__ == "__main__":
    main()
