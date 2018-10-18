import argparse
import select
import socket
import sys
import signal
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
import hmac

# define some globals
HOST = ''
SOCKET_LIST = []


def handler(signum, frame):
    """ handle a SIGINT (ctrl-C) keypress """
    for s in SOCKET_LIST:  # close all sockets
        s.close()
    sys.exit(0)


def wait_for_incoming_connection(port):
    """
    create a server socket and wait for incoming connection

    returns the server socket
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, port))
    s.listen(1)
    conn, addr = s.accept()
    SOCKET_LIST.append(s)
    SOCKET_LIST.append(conn)
    return conn


def connect_to_host(dst, port):
    """ connects to the host 'dst' """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((dst, port))
        SOCKET_LIST.append(s)
        return s
    except socket.error:
        print("Could not connect to %s." % dst)
        sys.exit(0)


def parse_command_line():
    """ parse the command-line """
    parser = argparse.ArgumentParser(description='Yinzhi\'s parser')

    parser.add_argument("-p", "--port",
                        dest="port",
                        type=int,
                        required=True,
                        help="port number")
    parser.add_argument("--confkey",
                        dest="confkey",
                        required=True,
                        help="confkey")
    parser.add_argument("--authkey",
                        dest="authkey",
                        required=True,
                        help="authkey")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-c", "--c",
                       dest="dst",
                       help="destination address")
    group.add_argument("-s", "--s",
                       dest="server",
                       action="store_true",
                       default=False,
                       help="start server mode")

    args = parser.parse_args()
    return args


def encrypt(confkey, authkey, msg):
    # hash confkey,authkey to 256 bits
    ckey = hashlib.sha256(confkey.encode('utf8')).digest()

    akey = hashlib.sha256(authkey.encode('utf8')).digest()

    # generate a random iv, size of 16 bytes
    iv = Random.new().read(16)

    length = len(msg)
    # s: size of message
    s = length.to_bytes(4, byteorder="little")

    # make the length of message = multiple of 16
    if length % 16 != 0:
        extraLen = 16 - length % 16
        msg += '\0' * extraLen

    # encrypt
    cipher = AES.new(ckey, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(msg.encode('utf8'))

    # do hmac
    h_mac = hmac.new(ciphertext, akey, hashlib.sha256).digest()

    # concat HMAC,s,ciphertext,iv as the final ciphertext and send it to the receiver
    ctext = h_mac + s + ciphertext + iv

    return ctext


def decrypt(confkey, authkey, ctext):
    # hash confkey,authkey to 256 bits
    ckey = hashlib.sha256(confkey.encode('utf8')).digest()

    akey = hashlib.sha256(authkey.encode('utf8')).digest()

    # split the ctext to HMAC, ciphertext, s, iv
    length = len(ctext)
    iv = ctext[length - 16:length]
    ciphertext = ctext[36:length - 16]
    s = ctext[32:36]
    h_mac_sender = ctext[0:32]

    # do hmac
    h_mac_reciver = hmac.new(ciphertext, akey, hashlib.sha256).digest()

    # verify anthentication using HMAC, if doesn't match, print error message and exit
    if hmac.compare_digest(h_mac_sender, h_mac_reciver) is False:
        print("HMAC doesn't match! Message is attacked!!!")
        exit(0)

    # decrypt
    cipher = AES.new(ckey, AES.MODE_CBC, iv)
    bplaintext = cipher.decrypt(ciphertext)
    ptext = bplaintext.decode('utf8')
    # print(s.decode('utf8'))
    # size = s.decode('utf8')
    # print(ptext)
    # ptext = ptext[0:size]

    return ptext


if __name__ == "__main__":

    options = parse_command_line()

    # catch when the user presses CTRL-C
    signal.signal(signal.SIGINT, handler)

    confkey = options.confkey
    authkey = options.authkey

    """
    The purpose of this code block is to either act as a server
    or a client.  The invariant is that when it returns, we'll
    have a socket (s), that is connected to the other party.
    """
    if options.server:
        s = wait_for_incoming_connection(options.port)
    elif options.dst:
        s = connect_to_host(options.dst, options.port)
    else:
        assert (False)  # this shouldn't happen

    rlist = [s, sys.stdin]  # wait for input either on s or stdin
    wlist = []
    xlist = []

    while True:
        (r, _, _) = select.select(rlist, wlist, xlist)
        if s in r:  # there is data to read from network
            data = s.recv(1024)
            if data == "" or len(data) == 0:  # other side ended connection
                break
            ptext = decrypt(confkey, authkey, data)
            sys.stdout.write(ptext)
            sys.stdout.flush()
        if sys.stdin in r:  # there is data to read from stdin
            data = sys.stdin.readline()
            if data == "":  # we closed STDIN
                break
            ctext = encrypt(confkey, authkey, data)
            s.send(ctext)

    """
            If we get here, then we've got an EOF in either stdin or our network.
            In either case, we iterate through our open sockets and close them.
    """
    for sock in SOCKET_LIST:
        sock.close()

    sys.exit(0)  # all's well that ends well!
