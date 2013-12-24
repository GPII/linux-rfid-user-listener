import logging
from smartcard.System import readers
from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.util import *
import httplib2
import sys

log = logging.getLogger("gpii")
log.setLevel(logging.DEBUG)
log.addHandler(logging.StreamHandler())

def get_connection(card=None):
    if card == None:
        # get all the available readers
        r = readers()
        reader = r[0]
        connection = reader.createConnection()
    else:
        connection = card.createConnection()
    connection.connect()
    #Load a key into location 0x00
    load_key = [0xFF, 0x82, 0x00, 0x00, 0x06, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
    data, sw1, sw2 = connection.transmit(load_key)
    return connection


def print_result(data,sw1,sw2):
    print "Command: %02X %02X %s" % (sw1, sw2, data)


def get_tag_model(tagconn):
    """Returns a tuple containing the model byte codes, and then human readable name.
    ie. ([0x00,0x01],"Mifare 1K")
    """
    atr = tagconn.getATR()
    model = atr[13:15]
    if model[0] == 0x00 and model[1] == 0x01:
        return (model,"Mifare 1K")
    elif model[0] == 0x00 and model[1] == 0x02:
        return (model,"Mifare 4K")
    elif model[0] == 0x00 and model[1] == 0x03:
        return (model,"Mifare Ultralight")
    elif model[0] == 0x00 and model[1] == 0x26:
        return (model,"Mifare Mini")
    else:
        raise NotImplementedError("We don't support this card model yet: [%02x,%02x]" % (model[0],model[1]))


def read_block(tagconn,blocknum,useauth=True):
    if useauth:
        # To authenticate the Block 0x04 with a {TYPE A, key number 0x00}. For PC/SC V2.07
        auth_block = [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, blocknum, 0x61, 0x00]
        data, sw1, sw2 = tagconn.transmit(auth_block)
    read_block = [0xFF,0xB0,0x00,blocknum,0x10]
    data, sw1, sw2 = tagconn.transmit(read_block)
    return data


def ultralight_page(pagenum):
    read_block = [0xFF,0xB0,0x00,blocknum,0x0F]
    data, sw1, sw2 = connection.transmit(read_block)
    return data

    
def dump_blocks(tagconn):
    """Dumps the blocks from the tag to screen for debugging. Currently we're
    only dumping enough blocks to take a look at where we would write our token.
    """
    for block in range(0,20):
        data = read_block(tagconn,block,True)
        s = ""
        for i in data:
            s = s+chr(i)
        print "%s %s %s" % (block,s,data)

    
def token_bytes_gen(token):
    """This is a generator that will return the characters of the token as
    bytes, and after that return 0's to pad out the memory blocks
    """
    cur = 0
    while 1:
        if cur < len(token):
            yield ord(token[cur])
            cur = cur+1
        else:
            yield 0


def get_gpii_token(tagconn):
    token = ""
    for i in range(4,7):
        block = read_block(tagconn,i)
        j = 0
        if i == 4:
            # Subtract 5 for the payload info, 2 for the language code
            tokenlen = block[3] - 5 - 2
            log.info("Length is: %s" % (tokenlen,))
            j = 11
        for byte in block[j:]:
            if byte == 0:
                return token
            token = token + chr(byte)
            if len(token) == tokenlen:
                return token
    return token


def write_gpii_token(tagconn,token):    
    tokgen = token_bytes_gen(token)
    for i in range(4,7):
        block = read_block(tagconn,i)
        print block
        j = 0
        if i == 4:
            j = 9
        while j < len(block): 
            block[j] = tokgen.next()
            j = j+1
        apdu = [0xFF,0xD6,0x00,i,0x10]
        apdu.extend(block)
        print block
        print apdu
        data, sw1, sw2 = tagconn.transmit(apdu)
        print_result(data,sw1,sw2)
        print "\n"


def gpii_login(token):
    h = httplib2.Http()
    resp, content = h.request("http://localhost:8081/user/%s/login" % (token,))
    log.info(resp)


def gpii_logout(token):
    h = httplib2.Http()
    resp, content = h.request("http://localhost:8081/user/%s/logout" % (token,))
    log.info(resp)


class GpiiTokenObserver(CardObserver):
    def __init__(self):
        super(GpiiTokenObserver, self).__init__()
        self.loggedin = False
        self.curtoken = None

    def update(self, observable, (addedcards, removedcards) ):
        for card in addedcards:
            conn = get_connection(card)
            token = get_gpii_token(conn)
            if self.loggedin:
                log.info("Logging out: %s" % (token))
                gpii_logout(token)
                self.loggedin = False
            else:
                log.info("Logging in: %s" % (token))
                gpii_login(token)
                self.loggedin = True


def run_gpii_listener():
    cardmonitor = CardMonitor()
    cardobserver = GpiiTokenObserver()
    cardmonitor.addObserver(cardobserver)
    while True:
        # We may want to add some runtime debug commands here,
        # but for now, this keeps us going while we wait.
        # TODO Daemonize this
        res = raw_input()


def main(args):
    """
This is a simple utility for performing operations on a NFC Tag
Reader and working with them for use in the GPII Project.

Usage:
pcscutil get model
    Print tag model

pcscutil get gpiitoken
    Print current GPII token

pcscutil dumpblocks
    Dump ascii and byte values for blocks on tag.

pcscutil runlistener
    Run the login/logout tag listener.

pcscutil help
    Print this help
    """
    if len(args) == 2 and args[0] == "get" and args[1] == "model":
        print get_tag_model(get_connection())[1]
    elif len(args) == 2 and args[0] == "get" and args[1] == "gpiitoken":
        print get_gpii_token(get_connection())
    elif len(args) == 1 and args[0] == "dumpblocks":
        dump_blocks(connection())
    elif len(args) == 1 and args[0] == "runlistener":
        run_gpii_listener()
    else:
        print main.__doc__

if __name__ == "__main__":    
    main(sys.argv[1:])
