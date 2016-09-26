import os
import sys


class ConfigHelper:
    def __init__(self):
        self.vault_url = self.get_from_env("VAULT_TOKEN")
        self.vault_token = self.get_from_env("VAULT_URL")
        self.logstash_ca_cn = self.get_from_env("LOGSTASH_CA_CN")
        self.logstash_server_cn = self.get_from_env("LOGSTASH_SERVER_CN")
        self.logstash_country = self.get_from_env("LOGSTASH_COUNTRY")
        self.logstash_state = self.get_from_env("LOGSTASH_STATE")
        self.logstash_city = self.get_from_env("LOGSTASH_CITY")
        self.key_password = self.get_from_env("KEY_PASSWORD")
        return

    @classmethod
    def get_from_env(cls, k):
        retval = os.getenv(k)
        if retval is None:
            print "Required config variable not set: %s" % k
            print "Unable to continue.  Exiting."
            sys.exit(2)
        return retval
