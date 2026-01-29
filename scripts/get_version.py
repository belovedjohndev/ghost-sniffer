import re


def main():
    with open("ghost_sniffer.py", "r", encoding="utf-8") as handle:
        data = handle.read()
    match = re.search(r'TOOL_VERSION\s*=\s*"([^"]+)"', data)
    if match:
        print(match.group(1))


if __name__ == "__main__":
    main()
