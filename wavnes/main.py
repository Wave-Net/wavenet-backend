from wavnes.server import start_server


async def main():
    await start_server("localhost", 8765)
