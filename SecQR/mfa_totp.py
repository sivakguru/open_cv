import pyotp
from omegaconf import OmegaConf

conf = OmegaConf.load('secrets.yaml')
secret_key = conf.totp.secret

################### TOTP Configuration ###################
# uri = pyotp.totp.TOTP(secret_key).provisioning_uri(name='sivakguru', issuer_name='SecQR')

# import segno
# segno.make(uri, error='H').save('totp.png', scale=20)
#########################################################

# TOTP Verification
def mfa_verify(otp):
    totp = pyotp.TOTP(secret_key)
    if totp.verify(otp):
        return True
    else:
        return False