import asyncio
import bonsai
from aiohttp import web
from itsdangerous import TimestampSigner, SignatureExpired, BadSignature
from cryptography import fernet


class LdapAuth:

    settings = {
        'LDAP_SERVER': 'ldap://SERVER:PORT',
        'LDAP_BASE_OBJ': 'dc=example,dc=com',
        'LDAP_USER_QUERY': '(userPrincipalName={})',
        'LDAP_DEFAULT_DOMAIN': 'example.com',
        'LDAP_ALLOWED_GROUPS': ("LDAP_GROUP_1", "LDAP_GROUP_2"),
    }

    def __init__(self, loop):
        self.loop = loop
        self.secret = fernet.Fernet.generate_key()
        self.key_signer = TimestampSigner(self.secret)
        self.client = bonsai.LDAPClient(self.settings['LDAP_SERVER'])

    async def authenticate(self, username=None, password=None):
        if '@' not in username:
            username = "{user}@{domain}". \
                format(user=username, domain=self.settings['LDAP_DEFAULT_DOMAIN'])

        user_dct = await self.ldap_auth(username, password)
        if user_dct is None:
            return None

        auth = {
            'auth': True,
            'user': {
                'name': username,
                'id': user_dct.get('id'),
                'last_name': user_dct.get('last_name'),
                'first_name': user_dct.get('first_name')
            }
        }

        return auth

    async def ldap_auth(self, user, password):
        self.client.set_credentials(
            "DIGEST-MD5", (user.split('@')[0], password, None, None)
        )
        async with self.client.connect(is_async=True) as conn:
            search = await conn.search(
                self.settings['LDAP_BASE_OBJ'],
                bonsai.LDAPSearchScope.SUB,
                self.settings['LDAP_USER_QUERY'].format(user),
                attrlist=['cn', 'sn', 'givenName', 'memberOf']
            )

            if search:
                if len(search) == 1:
                    ldap_user = search[0]
                    id = self.key_signer.sign(user)

                    return {
                        'id': id.decode('ascii'),
                        'name': str(ldap_user['cn'][0]),
                        'first_name': str(ldap_user['givenName'][0]),
                        'last_name': str(ldap_user['sn'][0]),
                        'groups': ldap_user['memberOf']
                    }
                else:
                    raise RuntimeError("Two users with same login")

    async def auth(self, request):
        data = await request.post()

        username = data.get('username')
        password = data.get('password')

        task = await self.authenticate(username, password)
        cookie = 'AUTH_SESSION={}; Path=/'.format(
            task['user'].get('id')
        )
        headers = {'Set-Cookie': cookie}

        return web.json_response(task, headers=headers)

    async def check_auth(self, request):
        cookie = request.cookies.get('AUTH_SESSION')

        if not cookie:
            return web.json_response({"auth": False})

        try:
            login = self.key_signer.unsign(cookie.encode('ascii'), max_age=36000)
        except (SignatureExpired, BadSignature):
            unset_cookie = 'AUTH_SESSION={}; Path=/; Expires=1;'.format(cookie)
            headers = {'Set-Cookie': unset_cookie}

            return web.json_response({"auth": False}, headers=headers)

        return web.json_response({
            "auth": True,
            "time_left": 3600,
            "user": login.decode('ascii')
        })

    def create_app(self):
        app = web.Application(loop=self.loop)
        app.router.add_route('POST', '/api/auth', self.auth)
        app.router.add_route('GET', '/api/auth/check', self.check_auth)

        return app


loop = asyncio.get_event_loop()
loop.set_debug(True)
auth_api = LdapAuth(loop)
app = auth_api.create_app()
web.run_app(app, host='0.0.0.0', port=8081)

