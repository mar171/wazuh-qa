#!/var/ossec/framework/python/bin/python3
# Send msg to WDB
import socket
import struct
import time
import sys

ADDR = '/var/ossec/queue/db/wdb'
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(ADDR)
if len(sys.argv) == 4:
    first_id = int(sys.argv[1])
    last_id = int(sys.argv[2])
    node_name = str(sys.argv[3])
else:
    print("./unsync.py <first_id> <last_id> <node_name>")
    sys.exit(1)
def send_msg(msg):
    msg = struct.pack('<I', len(msg)) + msg.encode()
    # Send msg
    sock.send(msg)
    # Receive response
    data = sock.recv(4)
    data_size = struct.unpack('<I', data[0:4])[0]
    data = sock.recv(data_size).decode(encoding='utf-8', errors='ignore').split(" ", 1)
    return data
msg = f'global sql UPDATE agent SET node_name = "{node_name}" where id>{first_id} and id<={last_id}'
send_msg(msg)
msg = f'global sql UPDATE agent SET version="Wazuh v4.0.0" where id>{first_id} and id<={last_id}'
send_msg(msg)

try:
    while True:
        msg = f'global sql UPDATE agent SET sync_status="syncreq", node_name="{node_name}", last_keepalive="{int(time.time())}", connection_status="active" where id>{first_id} and id<={last_id}'
        send_msg(msg)
        time.sleep(10)
except KeyboardInterrupt:
    print("Closing socket")
    sock.close()
except Exception:
    print("Closing socket")
    sock.close()
