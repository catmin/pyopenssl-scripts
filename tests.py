

import unittest

from ca import SampleCa, FileStore


class SmokeTests(unittest.TestCase):

    def test_create_ca(self):
        ca = SampleCa(auto_store=True)
        ca.create_ca_cert()
        # openssl x509 -in pki/cacert.pem -noout -text
        # TODO check CN, Version, date, algo

    def test_create_server(self):
        #store = FileStore("pki") 
        #store.set_serial("1001")
        ca = SampleCa(auto_store=True)
        ca.create_ca_cert()
        ca.create_server_cert("www.example.org")
        # openssl x509 -in pki/cacert.pem -noout -text
        # TODO check CN, Version, date, keyusage
        
    



def main():
    unittest.main()

if __name__ == '__main__':
    main()

