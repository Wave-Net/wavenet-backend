import argparse
from wavnes.server import start_server
from wavnes.sniffer import Sniffer


async def main(debug=False):
    if debug:
        sniffer = Sniffer(debug=True)
        await sniffer.start_sniff()
    else:
        await start_server("localhost", 8765)


if __name__ == "__main__":
    import asyncio

    parser = argparse.ArgumentParser(description="WebSocket server for packet capture")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()

    asyncio.run(main(debug=args.debug))
