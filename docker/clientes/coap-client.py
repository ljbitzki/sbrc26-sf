import asyncio
import sys
from aiocoap import *

async def main(var):
    protocol = await Context.create_client_context()
    request = Message(code=GET, uri="coap://" + (sys.argv[1]) + "/" + str(var))
    response = await protocol.request(request).response

if __name__ == "__main__":
    svar_string = sys.argv[2]
    asyncio.run(main(0))