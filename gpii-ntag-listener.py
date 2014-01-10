import httplib2
import nfc
import nfc.ndef
import logging
logging.basicConfig()


def gpii_login(token):
    h = httplib2.Http()
    resp, content = h.request("http://localhost:8081/user/%s/login" % (token,))
    logging.info(resp)


def gpii_logout(token):
    h = httplib2.Http()
    resp, content = h.request("http://localhost:8081/user/%s/logout" % (token,))
    logging.info(resp)


class GpiiNtagListener(object):
    def __init__(self):
        self.logged_in = False
        self.username = ''
    
    def read_tag(self, tag):
        if tag.ndef:
            record = tag.ndef.message[0]
            if record.type == "urn:nfc:wkt:T":
                text = nfc.ndef.TextRecord( record )
                if self.logged_in:
                    print "Logging out with ", text.text
                    gpii_logout(text.text)
                    self.logged_in = False
                else:
                    print "Logging in with ", text.text
                    gpii_login(text.text)
                    self.logged_in = True
        return True
    
    def main(self):
        with nfc.ContactlessFrontend('usb') as clf:
            while True:
                print "Please touch a tag to login/out of GPII"
                clf.connect(rdwr={'on-connect': self.read_tag})
            

if __name__ == '__main__':
    GpiiNtagListener().main()
