import time
import M2Crypto


class CryptoMart(object):
    """ Inspired by and adapted from https://gist.github.com/eskil/2338529 """
    def __init__(self, config):
        self.ca_cn = config.logstash_ca_cn
        self.server_cn = config.logstash_server_cn
        self.logstash_country = config.logstash_country
        self.logstash_state = config.logstash_state
        self.logstash_city = config.logstash_city
        self.expiration_days = 365
        self.key_password = config.key_password
        self.ca_cert = None
        self.ca_private_key = None
        self.ca_public_key = None
        self.cert_serial = 1
        self.set_ca_material()
        return

    @classmethod
    def passwdgen(cls, *arg, **kwargs):
        return 'kpwdddd'

    def set_ca_material(self):
        ca_cert, ca_privkey, ca_pubkey = self.make_ca_cert()
        self.ca_cert = ca_cert
        self.ca_pubkey = ca_pubkey
        self.ca_privkey = ca_privkey
        self.cert_serial = self.cert_serial + 1
        return

    def make_ca_issuer(self):
        issuer = M2Crypto.X509.X509_Name()
        issuer.C = self.logstash_country
        issuer.CN = "sitch_selfsigned_ca"
        issuer.ST = self.logstash_state
        issuer.L = self.logstash_state
        issuer.O = "SelfSignedSITCH"
        return issuer

    def make_ca_cert(self):
        request, pk = self.make_request(2048, self.ca_cn)
        pubkey = request.get_pubkey()
        cert = M2Crypto.X509.X509()
        cert.set_serial_number(self.cert_serial)
        cert.set_version(2)
        self.make_cert_valid(cert)
        cert.set_issuer(self.make_ca_issuer())
        cert.set_subject(cert.get_issuer())
        cert.set_pubkey(pubkey)
        cert.add_ext(M2Crypto.X509.new_extension('basicConstraints',
                                                 'CA:TRUE'))
        cert.add_ext(M2Crypto.X509.new_extension('subjectKeyIdentifier',
                                                 cert.get_fingerprint()))
        cert.sign(pk, 'sha256')
        return cert, pk, pubkey

    def make_casigned_cert(self, cn):
        """
        Create a signed cert + private key.
        """
        cert_req, privkey = self.make_request(2048, cn=cn)
        cert = self.make_cert()
        cert.set_subject(cert_req.get_subject())
        cert.set_pubkey(cert_req.get_pubkey())
        cert.sign(self.ca_privkey, 'sha256')
        self.cert_serial = self.cert_serial + 1
        return cert, privkey

    def make_cert(self):
        """
        Make a certificate.
        Returns a new cert.
        """
        cert = M2Crypto.X509.X509()
        cert.set_serial_number(self.cert_serial)
        cert.set_version(2)
        self.make_cert_valid(cert)
        cert.add_ext(M2Crypto.X509.new_extension('nsComment', 'SSL sever'))
        return cert

    def make_cert_valid(self, cert):
        t = long(time.time())
        now = M2Crypto.ASN1.ASN1_UTCTIME()
        now.set_time(t)
        expire = M2Crypto.ASN1.ASN1_UTCTIME()
        expire.set_time(t + self.expiration_days * 24 * 60 * 60)
        cert.set_not_before(now)
        cert.set_not_after(expire)

    def make_request(self, bits, cn):
        """
        Create a X509 request with the given number of bits in they key.
        Args:
          bits -- number of RSA key bits
          cn -- common name in the request
        Returns a X509 request and the private key (EVP)
        """
        pk = M2Crypto.EVP.PKey()
        x = M2Crypto.X509.Request()
        rsa = M2Crypto.RSA.gen_key(bits, 65537, lambda: None)
        pk.assign_rsa(rsa)
        x.set_pubkey(pk)
        name = x.get_subject()
        name.C = self.logstash_country
        name.CN = cn
        name.ST = self.logstash_state
        name.O = 'SITCH'
        name.OU = 'Delivery'
        x.sign(pk, 'sha256')
        return x, pk
