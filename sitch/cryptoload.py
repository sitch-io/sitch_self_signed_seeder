import sitchlib


config = sitchlib.ConfigHelper()
vault_obj = sitchlib.VaultObject(config)

# Set policies...
vault_obj.set_policies()

# Load crypto material into vault...
vault_obj.set_crypto()

# Generate tokens...
print "\nClient token is: "
token = vault_obj.client.create_token(policies=['client'], lease='3600h')
print token
print "\nServer token is: "
token = vault_obj.client.create_token(policies=['server'], lease='3600h')
print token
