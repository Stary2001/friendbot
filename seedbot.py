import sys
import logging
import hashlib
import struct
import time
import requests
import base64
import random
import threading
import queue
import yaml
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from datetime import datetime, timedelta

#import sqlite3

# sys.path fuckery
# dont try this at home, kids
sys.path.append("./NintendoClients")

from nintendo.nex import backend, authentication, friends, nintendo_notification
from nintendo import account

logging.basicConfig(level=logging.WARN)

def nintendo_base64_encode(data):
        return base64.b64encode(data).decode('ascii').replace('+', '.').replace('/', '-').replace('=', '*')

def nintendo_base64_decode(s):
        return base64.b64decode(s.replace('.', '+').replace('-', '/').replace('*', '='))

#db = sqlite3.connect('friends.db')
#db_cursor = db.cursor()

#db_cursor.execute("create table if not exists pending_friends (fc text, pid int, added datetime, expiry datetime)")
#db_cursor.execute("create table if not exists friends (pid int)")
#db.commit()

identity_path = "identity.yaml"
if len(sys.argv) >= 2:
	identity_path = sys.argv[1]
identity = yaml.load(open(identity_path, 'r'))

blob = {
  'gameid': b'00003200',
  'sdkver': b'000000',
  'titleid': b'0004013000003202',
  'gamecd': b'----',
  'gamever': b'0010',
  'mediatype': b'0',
  'makercd': b'00',
  'servertype': b'L1',
  'fpdver': b'000B',
  'unitcd': b'2', # ?
  'macadr': identity['mac_address'].encode('ascii'), # 3DS' wifi MAC
  'bssid': identity['bssid'].encode('ascii'), # current AP's wifi MAC
  'apinfo': identity['apinfo'].encode('ascii'),
  'fcdcert': open(identity['cert_filename'], 'rb').read(),
  'devname': identity['name'].encode('utf16'),
  'devtime': b'340605055519',
  'lang': b'01',
  'region': b'02',
  'csnum': identity['serial'].encode('ascii'),
  'uidhmac': identity['uid_hmac'].encode('ascii'), # TODO: figure out how this is calculated. b'213dc099',
  'userid': str(identity['user_id']).encode('ascii'),
  'action': b'LOGIN',
  'ingamesn': b''
}

blob_enc = {}
for k in blob:
	blob_enc[k] = nintendo_base64_encode(blob[k])
print(f"Getting a NASC token for {blob['csnum'].decode('ascii')}..")
resp = requests.post("https://nasc.nintendowifi.net/ac", headers={'User-Agent': 'CTR FPD/000B', 'X-GameID': '00003200'}, data=blob_enc, cert='ClCertA.pem', verify=False)

bits = dict(map(lambda a: a.split("="), resp.text.split("&")))
bits_dec = {}
for k in bits:
	bits_dec[k] = nintendo_base64_decode(bits[k])
host, port = bits_dec['locator'].decode().split(':')
port = int(port)

pid = str(identity['user_id'])
password = identity['password']
my_friendseed = identity['lfcs']

backend = backend.BackEndClient(
	friends.FriendsTitle.ACCESS_KEY,
	friends.FriendsTitle.NEX_VERSION,
	backend.Settings("friends.cfg")
)
backend.connect(host, port)
backend.login(
	pid, password,
    auth_info = None,
	login_data = authentication.AccountExtraInfo(168823937, 2134704128, 0, bits['token']),
)

client = friends.Friends3DSClient(backend)
status = 'Seedbot - up for {}.\nGot {} FCs.'
fc_count = 0

#print(db.execute("select pid from friends").fetchall())

all = client.get_all_friends()
print(len(all),"friends")
print(all)


start_time = datetime.utcnow()
game_shuffle_time = datetime.utcnow()

random_games =  [
	# RCMDIAX games
	0x000400000F707300, 0x000400000F708A00, 0x000400000F708B00, 0x000400000F708E00, 0x000400000F709300, 0x000400000F709D00, 0x000400000F70A400, 0x000400000F70AD00, 0x000400000F70AC00, 0x000400000F70B000, 0x000400000F70C300, 0x000400000F70C500, 0x000400000F70D200, 0x000400000F70D100, 0x000400000F70F800, 0x000400000F710400, 0x000400000F710300, 0x000400000F710D00,
	# Fat Dragons
	0x00040000001D0300,
	# Operation COBRA
	0x000400000f70c600
]

playing_title_id = random.choice(random_games)

def update_presence():
	global game_shuffle_time
	global playing_title_id
	global fc_count

	#queue_length = len(db_cursor.execute("select * from pending_friends").fetchall())
	uptime = datetime.utcnow() - start_time
	uptime_str = ""
	if uptime.days > 7:
		uptime_str += f"{uptime.days//7}w"
	if uptime.days > 0:
		uptime_str += f"{uptime.days % 7}d"
	if uptime.seconds >= 3600:
		uptime_str += f"{uptime.seconds // 3600}h"
	if uptime.seconds >= 60:
		uptime_str += f"{(uptime.seconds % 3600) // 60}m"
	uptime_str += f"{uptime.seconds % 60}s"

	if datetime.utcnow() - game_shuffle_time > timedelta(minutes=1):
		game_shuffle_time = datetime.utcnow()
		playing_title_id = random.choice(random_games)

	s = status.format(uptime_str, fc_count)

	presence = friends.NintendoPresenceV1(0xffffffff, friends.GameKey(playing_title_id, 0), s, 0, 0, 0, 0, 0, 0, b"")
	client.update_presence(presence, True)
update_presence()

def pid_to_fc(principal_id):
	checksum = hashlib.sha1(struct.pack('<L', principal_id)).digest()[0] >> 1
	return str(principal_id | checksum << 32)

class NotificationHandler(nintendo_notification.NintendoNotificationHandler):
	def __init__(self):
		self.name_cache = {}

	def process_notification_event(self, event):
		global lfcs_queue
		if event.type == nintendo_notification.NotificationType.FRIEND_REQUEST_COMPLETE:
			print("Friend request completed for pid {}!!!!!".format(event.pid))
			lfcs_queue.put(event.pid)

backend.nintendo_notification_server.handler = NotificationHandler()

lfcs_queue = queue.Queue()
sh_running = True
#sh_path = "http://seed.9net.org"
sh_path = "http://seedhelper3.figgyc.uk"
getfc_interval = 5
spinner = 0

def sh_thread():
	global client, my_friendseed, sh_running, sh_path, lfcs_queue, getfc_interval, spinner, fc_count, db
	while sh_running:
		try:
			if not lfcs_queue.empty():
				pid = lfcs_queue.get()
				rel = client.sync_friend(my_friendseed, [pid], [])[0]
				fc = pid_to_fc(pid)
				print("got fc in queue", fc)
				fc_count += 1
				lfcs_res = requests.get(sh_path+"/lfcs/{}".format(fc), params={'lfcs': '{:016x}'.format(rel.friend_code)})
				if lfcs_res.status_code == 200:
					print("lfcs result: ", lfcs_res.text)

			fc_list = requests.get(sh_path+"/getfcs")
			if fc_list.status_code != 200:
				time.sleep(getfc_interval)
				continue
			else:
				if fc_list.text == 'nothing':
					msg = "empty " + "|/-\\"[spinner]
					spinner = spinner + 1
					if spinner > 3:
						spinner = 0
					print("\x1b[2K" + msg + "\x08"*len(msg), end="")
					sys.stdout.flush()
					time.sleep(getfc_interval)
					continue

			for fc in fc_list.text.split("\n"):
				if fc == '':
					continue
				if fc == 'nothing':
					break
				print("processing ", fc)
				#db.execute("insert into friends (pid) values (?)", (int(fc) & 0xffffffff))
				#db.commit()
				rel = client.add_friend_by_principal_id(my_friendseed, int(fc) & 0xffffffff)

				resp = requests.get(sh_path+"/added/{}".format(fc))
				if resp.status_code == 200:
					print("add result: ", resp.text)

				if rel.is_complete == True:
					print("got lfcs for ", fc)
					fc_count += 1
					resp = requests.get(sh_path+"/lfcs/{}".format(fc), params={'lfcs': '{:016x}'.format(rel.friend_code)})
					if resp.status_code == 200:
						print("lfcs result: ", resp.text)

			time.sleep(getfc_interval)
		except Exception as e:
			print("Got exception!!", e)

sh_thread_obj = threading.Thread(target=sh_thread)
sh_thread_obj.daemon = True
sh_thread_obj.start()

def presence_thread():
	while True:
		time.sleep(30)
		update_presence()

p_thread_obj = threading.Thread(target=presence_thread)
p_thread_obj.daemon = True
p_thread_obj.start()

while True:
	input("")

sh_running = False
client.update_presence(friends.NintendoPresenceV1(0xffffffff, friends.GameKey(0x00040000001B8700, 0), 'shutting down..', 0, 0, 0, 0, 0, 0, b""), False)

backend.close()
