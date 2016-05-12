

__author__ = 'catmin'

from OpenSSL import crypto, SSL



import os 

class FileStore:

    def __init__(self, target_dir=None):
        if target_dir:
            self.target_dir = target_dir
        else:
            self.target_dir = "."


    def get_abs_path(self, rel_path):
        return os.path.join(self.target_dir, rel_path)

    @staticmethod
    def get_cert_pem(x509_cert):
        return crypto.dump_certificate(crypto.FILETYPE_PEM, x509_cert)

    @staticmethod
    def get_key_pem(x509_key):
        return crypto.dump_privatekey(crypto.FILETYPE_PEM, x509_key)

    def store_serial(self, serial):
        open(self.get_abs_path("serial"), 'w').write(serial)
        return

    def get_serial(self):
        serial = int(open(self.get_abs_path("serial"), 'r').read())
        return serial

    def set_serial(self, serial):
        open(self.get_abs_path("serial"), 'w').write(str(serial))


    def store_ca(self, cert, key):
        cacert_path = self.get_abs_path("cacert.pem") 
        cakey_path = self.get_abs_path("cakey.pem") 
        with open(cacert_path, 'w') as certificate:
            certificate.write(self.get_cert_pem(cert))
        with open(cakey_path, 'w') as privatekey:
            privatekey.write(self.get_key_pem(key))
        return cert, key

    def get_ca(self):
        cert_path = self.get_abs_path("cacert.pem") 
        key_path = self.get_abs_path("cakey.pem") 
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(cert_path).read())
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(key_path).read())
        return cert, key

    def store_server_cert(self, cert, key):
        cert_path = self.get_abs_path("certs/cert{0}.pem".format(cert.get_serial_number())) 
        key_path = self.get_abs_path("private/key{0}.pem".format(cert.get_serial_number())) 
        with open(cert_path, 'w') as certificate:
            certificate.write(self.get_cert_pem(cert))
        with open(key_path, 'w') as privatekey:
            privatekey.write(self.get_key_pem(key))
        return cert, key




class SampleCa:

    """
    creates certificates and stores them locally into the filesystem


    usage:

    ca = SampleCa(auto_store=True) # do persistence automatically
    ca.create_ca_cert() # or ca.load_from_files()
    
    cert, key = ca.create_server_cert()

    """

    # ca cert expiration time 
    CA_VALID = 10*365*24*60*60 # 10 years
    # client / server cert expiration time
    CERT_VALID = 1*365*24*60*60 # 1 year
    # ca bit length
    CA_BITS = 4096
    # server cert bit length
    SERVER_BITS = 2048
    # client cert bit length 
    NERF_BITS = 2048
    # default signing algorithm
    SIGN_ALGO = "sha256"
    # initial serial
    INIT_SERIAL = 1000

    def __init__(self, auto_store=False, store=None):
        if not store:
            store = FileStore("pki")
            self.load_ca_from_store(store)
        self.auto_store = auto_store
        return

    def load_ca_from_store(self, store):
        # get ca cert from store
        cert, key = store.get_ca()
        serial = store.get_serial()
        # remember store
        self.store = store 
        # assign to object
        self.ca_cert = cert
        self.ca_key = key
        self.serial = serial
        return cert, key 

    def get_next_serial_nr(self):
        self.serial += 1 
        #TODO save serial?
        self.store.set_serial(self.serial)
        return self.serial
        
    def gen_key(self, bits_len):
        """
        create a RSA key with defined bit length
        """
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, bits_len)
        return key

    def create_ca_cert(self):
        """
        create ca certificate and key and store it
        :return:
        """
        key = self.gen_key(self.CA_BITS)

        cert = crypto.X509()
        cert.set_version(0x2) # version 3
        cert.get_subject().O = "EXAMPLE"
        cert.get_subject().CN = "CA"
        # initial serial is used for ca cert
        cert.set_serial_number(self.get_next_serial_nr())
        # start today
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(self.CA_VALID)
        # self sign
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, self.SIGN_ALGO)

        # store
        if self.auto_store:
            self.store.store_ca(cert, key)    

        # for future use of the object
        self.ca_cert = cert
        self.ca_key = key

        return self.ca_cert, self.ca_key



    def create_server_cert(self, fqdn):
        """
        create a https listener certificate
        ca must be loaded
        :param fqdn: full qualified domain name of the machine
        :return: cert, key
        """

        cert = crypto.X509()
        cert.set_version(0x2) # version 3
        cert.get_subject().O = "EXAMPLE"
        cert.get_subject().CN = fqdn
        cert.set_serial_number(self.get_next_serial_nr())
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(self.CERT_VALID)
        cert.set_issuer(self.ca_cert.get_subject())
        base_constraints = ([
            crypto.X509Extension("keyUsage", False, "Digital Signature, Non Repudiation, Key Encipherment"),
            crypto.X509Extension("basicConstraints", False, "CA:FALSE"),
            #crypto.X509Extension("extendedKeyUsage",False,"serverAuth"), for client auth
        ])
        x509_extensions = base_constraints
        cert.add_extensions(x509_extensions)
        key = self.gen_key(self.SERVER_BITS)
        cert.set_pubkey(key)
        cert.sign(self.ca_key, self.SIGN_ALGO)

        # store to database
        if self.auto_store:
            self.store.store_server_cert(cert, key)

        return cert, key







