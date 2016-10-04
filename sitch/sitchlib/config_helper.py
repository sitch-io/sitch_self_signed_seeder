import os
import sys


class ConfigHelper:
    def __init__(self):
        self.vault_url = self.get_from_env("VAULT_URL")
        self.vault_token = self.get_from_env("VAULT_TOKEN")
        self.logstash_ca_cert = self.get_from_env("CA_CERT")
        self.logstash_server_cert = self.get_from_env("SERVER_CERT")
        self.logstash_server_key = self.get_from_env("SERVER_KEY")
        self.logstash_client_cert = self.get_from_env("CLIENT_CERT")
        self.logstash_client_key = self.get_from_env("CLIENT_KEY")
        self.vault_server_policy = """
        path "secret/server" {
            policy = "read"
        }
        """
        self.vault_client_policy = """
        path "secret/client" {
            policy = "read"
        }
        """
        return

    @classmethod
    def get_from_env(cls, k):
        retval = os.getenv(k)
        if retval is None:
            print "Required config variable not set: %s" % k
            print "Unable to continue.  Exiting."
            sys.exit(2)
        return retval
