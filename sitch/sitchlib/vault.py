import hvac


class VaultObject(object):
    def __init__(self, config):
        self.url = config.vault_url
        self.root_token = config.vault_token
        self.client = hvac.Client(url=config.vault_url, token=self.root_token)
        self.logstash_ca_cert = config.logstash_ca_cert
        self.logstash_svr_crt = self.get_from_file(config.logstash_server_cert)
        self.logstash_svr_key = self.get_from_file(config.logstash_server_key)
        self.logstash_cli_crt = self.get_from_file(config.logstash_client_cert)
        self.logstash_cli_key = self.get_from_file(config.logstash_client_key)
        self.vault_client_policy = config.vault_client_policy
        self.vault_server_policy = config.vault_server_policy
        print "Vault url: %s" % config.vault_url
        return

    @classmethod
    def get_from_file(cls, filename):
        with open(filename, 'r') as infile:
            contents = infile.read()
        return contents

    def set_policies(self):
        coll = {"server": self.vault_server_policy,
                "client": self.vault_client_policy}
        for pol in coll.items():
            self.client.set_policy(pol[0], pol[1])

    def set_crypto(self):
        print "Setting server key material..."
        self.client.write("secret/server", crt=self.logstash_svr_crt,
                          key=self.logstash_svr_key,
                          ca=self.logstash_ca_cert)
        self.client.write("secret/client", crt=self.logstash_cli_crt,
                          key=self.logstash_cli_key,
                          ca=self.logstash_ca_cert)
