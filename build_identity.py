import base64
import yaml
import urllib.parse

def nintendo_base64_encode(data):
        return base64.b64encode(data).decode('ascii').replace('+', '.').replace('/', '-').replace('=', '*')

def nintendo_base64_decode(s):
        return base64.b64decode(s.replace('.', '+').replace('-', '/').replace('*', '='))

n = urllib.parse.unquote(input("Enter full string of nasc request: ").strip())

bits = dict(map(lambda a: a.split("="), n.split("&")))
bits_dec = {}
for k in bits:
    bits_dec[k] = nintendo_base64_decode(bits[k])

cert = bits_dec['fcdcert']
serial = bits_dec['csnum'].decode('ascii')
open('ctcert_' + serial + '.bin', 'wb').write(cert)

a = {
	'mac_address': bits_dec['macadr'].decode('ascii'),
	'serial': serial,
	'name': bits_dec['devname'].decode('utf-16'),
	'cert_filename': 'ctcert_' + serial+'.bin',
	'user_id': int(bits_dec['userid'].decode('ascii')),
	'uid_hmac': bits_dec['uidhmac'].decode('ascii'),
	'bssid': bits_dec['bssid'].decode('ascii'),
	'apinfo': bits_dec['apinfo'].decode('ascii'),
	'lfcs': 'REPLACEME',
	'password': 'REPLACEME',
}

a = yaml.dump(a, default_flow_style=False)
open(f'identity_{serial}.yaml','w').write(a)
