# url of the dynafed url. usually ends in "/myfed/"
BASE_DYNAFED_URL = "http://129.215.193.57/myfed/"

# the name of the token which will be used to pass encrypted information
# this must match the expected token name in the authorisation plugin script
AUTH_TOKEN_NAME = "auth_token"

# simple map of id supplied in request credential to their private key
ID_TO_KEY = { "<some-id>": "<some-key>"}

# map of id to roles 
ID_TO_ROLES = { "<some-id>": "<some-roles>"}

# encrytion key length must be a multiple of 8, 16 or 32
# or AES algorithm wll fail
# the values must match the values specified in the authorisation plugin script
# for example, use a uid here
ENCRYPTION_KEY = "0c34-7877-4d02-be9f-42ee80f2cb71"	
ENCRYTION_BLOCK_SIZE = 32
