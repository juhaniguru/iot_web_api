# for asymmetrically signed tokens. You should always prefer this over symmetrically signed
import time

import jwt


class BaseToken:
    def create(self, claims):
        pass

    def validate(self, t):
        pass



class AsymmetricToken(BaseToken):
    def __init__(self):
        with open('cert/id_rsa') as f:
            self.private = f.read()
        with open('cert/id_rsa.pub') as f:
            self.public = f.read()

    def create(self, claims):

        now = time.time()
        issuer = 'iot'
        audience = 'iot'
        _type = claims['type']
        exp = claims['exp']
        sub = claims['sub']
        csrf = claims['csrf']

        data = {'iss': issuer, 'aud': audience, 'type': _type, 'sub': sub, 'iat': now, 'nbf': now - 10}
        if exp is not None:
            data['exp'] = exp
        if csrf is not None:
            data['csrf'] = csrf
        _token = jwt.encode(data, self.private, algorithm='RS512')
        return _token

    # decodes token, checks that it's not tampered with
    def validate(self, t):
        claims = jwt.decode(t, self.public, algorithms=['RS512'], audience='iot')
        return claims