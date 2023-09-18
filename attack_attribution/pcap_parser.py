import csv
import datetime
import glob
import json
import logging
import logging.handlers
import os
import re
import subprocess
import sys
import urllib

from ipwhois import IPWhois, IPDefinedError
#from db_model import AsnInfo, AttackAttribution, DnsQuery
from multiprocessing.connection import Client
#from peewee import IntegrityError, DateTimeField
from settings import CONFIG


class PCAPParser:
    def __init__(self):
        self.asn_dict = {}
        self.attack_attrib = []
        self.dns_data = []
        self.config = CONFIG
        
        # File to be parsed would be a command line argument
        self.pcap_filepath = sys.argv[1]
        self.pcap_filename = os.path.basename(sys.argv[1])
        self.prev_filename_to_scan = None
        self.prev_filepath = None
        
        # File time is important when backtracking. It allows us to decide
        # whether an earlier PCAP file would be needed
        if self.pcap_filename.startswith('mirroring'):
            self.file_creation_time_str = self.pcap_filename.split('_')[-1].split('.')[0]
            self.file_creation_time_date = datetime.datetime.strptime(
                self.file_creation_time_str,
                "%Y%m%d%H%M%S"
            )

            # Also compute the previous file name once
            # Get all file names and sort based on their creation time
            # (which is contained in the filename itself)
            # Glob is needed to use wildcard. Otherwise some goutputstream files get tracked as well
            # Since glob.glob gives full pathnames, we need os.path.basename to get only filename
            sorted_filenames = [
                os.path.basename(x[0]) for x in sorted(
                    [(fn, fn.split('_')[-1].split('.')[0]) for fn in glob.glob(self.config['mirroring_data']['pcap_dir'])],
                    key = lambda x: datetime.datetime.strptime(
                        x[1],"%Y%m%d%H%M%S")
                )
            ]           
            # If no previous file exists            
            if len(sorted_filenames) > 1:
                self.prev_filename_to_scan = sorted_filenames[sorted_filenames.index(
                    self.pcap_filename
                ) - 1]
                self.prev_filepath = os.path.join(
                    os.path.dirname(self.pcap_filepath),
                    self.prev_filename_to_scan
                )            
        
        # Check if log file exists. Create new file if it doesn't
        if not os.path.exists(self.config['logging']['logfile']):
            open(self.config['logging']['logfile'], "w").close()
        self.logger = logging.getLogger('backtracking')
        hdlr = logging.handlers.TimedRotatingFileHandler(
            self.config['logging']['logfile'],
            when=self.config['logging']['rotate_interval'],
            backupCount=self.config['logging']['backup_count']
            )
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        hdlr.setFormatter(formatter)
        self.logger.addHandler(hdlr) 
        self.logger.setLevel(self.config['logging']['log_level'])

    def download_and_insert_asn_info(self, ip_addr):
        """
        Given an IP address, this method gets registration data info of that IP and inserts in DB
        """
        try:
            obj = IPWhois(ip_addr)
            asn_results = obj.lookup_rdap(depth=1)
        except IPDefinedError as e:
            self.logger.debug("ipwhois.exceptions.IPDefinedError while getting information. Returning....")
            return

        # Also get VT ip-address info
        url = self.config['vt']['url']
        parameters = {'ip': ip_addr, 'apikey': self.config['vt']['api_key']}
        response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
        response_dict = {}
        try:
            response_dict = json.loads(response)
        except Exception as e:
            response_dict['response_code'] = 0

        try:
            AsnInfo.insert(
                asn = asn_results['asn'],
                ip = asn_results['query'],
                ip_in_vt_db = response_dict['response_code'],
                asn_cidr = asn_results['asn_cidr'],
                asn_country_code = asn_results['asn_country_code'],
                asn_desc = asn_results['asn_description'],
                network_handle = asn_results['network']['handle'],
                network_name = asn_results['network']['name']
            ).execute()
        except Exception:
            self.logger.info("Error when writing asn info to DB: {0}".format(sys.exc_info()))
            self.logger.debug("ASN Info: {0}".format(asn_results))

    def search_ip_pcap_file(self, filepath, file_data, dst_ip):
                
        self.logger.debug("Searching for {0} in {1}".format(dst_ip, os.path.basename(filepath)))
        
        # Loop through every line in the file to search for IP
        # Sample string from file
        # May 31, 2017 00:48:03.942689660 +08192.168.3.25192.168.3.224915240442Timestamps,GET /webs/description.xml HTTP/1.1\r\n,\r\n
        for each_line in file_data.split('\n'):
            tokens = each_line.split('\t')
            # Position 5 and 6 should contain columns 'data' and 'info'
            # 'any' would check if either 5 or 6 position strings contain the dst_ip
            # However, positions 5 and 6 may not exist in the first place and we catch such
            # exceptions by doing tokens[5:] which would generate an empty list if items not
            # present   
            
            if any(dst_ip in item for item in tokens[5:]):
                self.logger.debug("Found {0} in {1}".format(dst_ip, os.path.basename(filepath)))
                return tokens

        return None

    def detect_dns_queries(self):
        # Sometimes getting filenames with 'goutputstream' in them
        # It's a bug in Linux. For now handling such cases with IF stmt
        if not self.pcap_filename.startswith('mirroring'):
            self.logger.warning(
                "Ignoring invalid file: {0} for DNS requests".format(self.pcap_filename)
            )
            return

        self.logger.info("Looking for all DNS queries in {0}".format(self.pcap_filepath))
        # Find all DNS queries in PCAP file
        dns_cmd = 'tshark -r {0} -n -Y \'dns\' -n -T fields -e frame.time -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e dns.qry.name'.format(self.pcap_filepath)
        dns_queries = subprocess.Popen(
            dns_cmd,
            shell=True,
            stdout=subprocess.PIPE
        ).stdout.read()

        for each_dns_query in dns_queries.split('\n')[:-1]:
            dns_tokens = each_dns_query.split('\t')
            self.dns_data.append({
                'domain': dns_tokens[5],
                'dst_ip': dns_tokens[3],
                'dst_port': dns_tokens[4],
                'query_time': datetime.datetime.strptime(
                    dns_tokens[0][:-7],
                    "%b %d, %Y %H:%M:%S.%f"
                ),
                'src_ip': dns_tokens[1],
                'src_port': dns_tokens[2]
            })
        res = (DnsQuery.insert_many(self.dns_data).execute())
        self.logger.info(
            '{0} - Inserted records in dns_query table'.format(
                self.pcap_filename
        ))

    def detect_outbound_connections(self):
        # Sometimes getting filenames with 'goutputstream' in them
        # It's a bug in Linux. For now handling such cases with IF stmt
        if not self.pcap_filename.startswith('mirroring'):            
            self.logger.warning("Ignoring invalid file: {0}".format(self.pcap_filename))            
            return

        # Do not do in init method as this DB table might change from time to time
        # On the downside, we pull results from DB for every file to be processed
        """
        [YLA]
        for each_asn in AsnInfo.select():
            self.asn_dict[each_asn.ip] = [
                each_asn.network_name,
                each_asn.asn_country_code,
                each_asn.asn_desc,
                each_asn.asn_cidr
            ]
        """
       
        self.logger.info(
            '================ Processing file - {0} and previous file - {1} ================'.format(
                self.pcap_filename, self.prev_filename_to_scan
        ))

        # Include 239.255.255.250 TCP/5000 for UPnP
        # Find all outbound connections as those having SYN == 1 and ACK == 0
        #outbound_tcp_conn_cmd = 'tshark -r {0} -n -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.dst == 10.0.64.2/18" -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport -e tcp.srcport'.format(self.pcap_filepath)
        outbound_tcp_conn_cmd = 'tshark -r {0} -n -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0 and not(ip.dst == 239.255.255.250) and not(ip.dst == 10.0.64.0/18)" -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport -e tcp.srcport'.format(self.pcap_filepath)
        #outbound_tcp_conn_cmd = 'tshark -r {0} -n -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0 and not (ip.dst == 192.168.0.0/16)" -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport -e tcp.srcport'.format(self.pcap_filepath)
        outbound_tcp_attempts = subprocess.Popen(
            outbound_tcp_conn_cmd,
            shell=True,
            stdout=subprocess.PIPE
        ).stdout.read()
        # We ignore the last empty line
        # Every line is one outbound connection
        all_outbound_attempts = outbound_tcp_attempts.split('\n')[:-1]
        num_outbound_tcp_attempts = len(all_outbound_attempts)

        self.logger.debug(
           'Executed command - {0} for detecting outbound TCP connection attempts'.format(
               outbound_tcp_conn_cmd
        ))
            
        outbound_udp_conn_cmd = 'tshark -r {0} -n -Y "udp and not(ip.dst == 239.255.255.250) and not(ip.dst == 10.0.64.0/18)" -T fields -e frame.time -e ip.src -e ip.dst -e udp.dstport -e udp.srcport'.format(self.pcap_filepath)
        #outbound_udp_conn_cmd = 'tshark -r {0} -n -Y "udp and not (ip.dst == 192.168.0.0/16)" -T fields -e frame.time -e ip.src -e ip.dst -e udp.dstport -e udp.srcport'.format(self.pcap_filepath)
        outbound_udp_attempts = subprocess.Popen(
            outbound_udp_conn_cmd,
            shell=True,
            stdout=subprocess.PIPE
        ).stdout.read()
        # We ignore the last empty line
        # Every line is one outbound connection
        # Append UDP connections found to the existing list of TCP connections
        all_outbound_attempts.extend(outbound_udp_attempts.split('\n')[:-1])
        num_outbound_udp_attempts = len(outbound_udp_attempts.split('\n')[:-1])
                
        self.logger.debug(
           'Executed command - {0} for detecting outbound UDP connection attempts'.format(
               outbound_udp_conn_cmd
        ))
        
        num_all_outbound_attempts = len(all_outbound_attempts)        
        self.logger.info(
            '{0} outbound TCP attempts and {1} outbound UDP attempts detected in file {2}'.format(
                num_outbound_tcp_attempts,
                num_outbound_udp_attempts,
                self.pcap_filename
        ))
        
        if num_all_outbound_attempts < 1:            
            self.logger.info("No outbound attempts. Returning.....")
            return
    
        # Read the whole pcap file in one go and also the previous file
        # When backtracking, we only need TCP data because incoming connection can be only over HTTP or Telnet (and both are TCP)
        read_cur_pcap_file_cmd = 'tshark -r {0} -n -Y \'ip.dst == 10.0.96.0/18 || telnet\' -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport -e tcp.srcport -e telnet.data -e text'.format(
        #read_cur_pcap_file_cmd = 'tshark -r {0} -n -Y \'ip.dst == 192.168.3.0/27 || telnet\' -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport -e tcp.srcport -e telnet.data -e text'.format(
            self.pcap_filepath
        )
        cur_pcap_file_lines = subprocess.Popen(
            read_cur_pcap_file_cmd, shell=True, stdout=subprocess.PIPE
        ).stdout.read()        
        
        self.logger.debug(
           'Executed command - {0} for reading current pcap file data'.format(
               read_cur_pcap_file_cmd
        ))
                
        read_prev_pcap_file_cmd = 'tshark -r {0} -n -Y \'ip.dst == 10.0.96.0/18 || telnet\' -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport -e tcp.srcport -e telnet.data -e text'.format(
        #read_prev_pcap_file_cmd = 'tshark -r {0} -n -Y \'ip.dst == 192.168.3.0/27 || telnet\' -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport -e tcp.srcport -e telnet.data -e text'.format(
            self.prev_filepath
        )
        prev_pcap_file_lines = subprocess.Popen(
            read_prev_pcap_file_cmd, shell=True, stdout=subprocess.PIPE
        ).stdout.read()
        
        self.logger.debug(
           'Executed command - {0} for reading previous pcap file data'.format(
               read_prev_pcap_file_cmd
        ))
        
        loop_ctr = 1
        for each_line in all_outbound_attempts:

            outbound_conn_tokens = each_line.split('\t')
            outbound_dst_ip = outbound_conn_tokens[2]
            outbound_dst_port = int(outbound_conn_tokens[3])
            outbound_src_ip = outbound_conn_tokens[1]
            outbound_src_port = int(outbound_conn_tokens[4])
            outbound_conn_attempt_time = datetime.datetime.strptime(
                outbound_conn_tokens[0][:-7],
                "%b %d, %Y %H:%M:%S.%f"
            )

            # These are init values, will be changed only if attack is discovered
            attack_src_ip = None
            attack_src_port = None
            attack_attempt_time = None
            attack_data = None
            attack_info = None
            
            found = 1
            ip_search_result = self.search_ip_pcap_file(self.pcap_filepath, cur_pcap_file_lines, outbound_dst_ip)
            if ip_search_result is None:
                # Search in current file failed
                # Backtrack into previous file and search again
                ip_search_result = self.search_ip_pcap_file(self.prev_filepath, prev_pcap_file_lines, outbound_dst_ip)
                if ip_search_result is None:
                    found = 0

            if found:                    
                self.logger.info(
                    '***** Attack discovered for outbound IP: {0}'.format(outbound_dst_ip)
                )                
                attack_src_ip = ip_search_result[1]
                attack_src_port = ip_search_result[4]
                attack_attempt_time = datetime.datetime.strptime(
                    ip_search_result[0][:-7],
                    "%b %d, %Y %H:%M:%S.%f"
                )
                try:
                    attack_data = ip_search_result[5]
                except IndexError:
                    attack_data = ''
                    
                try:
                    attack_info = ip_search_result[6]
                except IndexError:
                    attack_info = ''

            self.attack_attrib.append({
                'outbound_dst_ip': outbound_dst_ip,
                'outbound_dst_port': outbound_dst_port,
                'outbound_src_ip': outbound_src_ip,
                'outbound_src_port': outbound_src_port,
                'outbound_conn_attempt_time': outbound_conn_attempt_time,
                'attack_src_ip': attack_src_ip,
                'attack_src_port': attack_src_port,
                'attack_attempt_time': attack_attempt_time,
                'attack_data': attack_data,
                'attack_info': attack_info
            })          
            
            # If outbound IP info doesn't exist in DB, then fetch it
            #if outbound_dst_ip not in self.asn_dict.keys():
            #    self.logger.info("Fetching ASN info for {0}".format(outbound_dst_ip))
            #    self.download_and_insert_asn_info(outbound_dst_ip)
            
            if loop_ctr % 50 == 0:                            
                self.logger.info(
                    '{0} - Done processing {1} of {2} attempts'.format(
                        self.pcap_filename, loop_ctr, num_all_outbound_attempts
                ))
                                
            loop_ctr += 1

        """
        [YLA]
        res = (AttackAttribution
               .insert_many(
                   self.attack_attrib
               ).execute()
        )
        self.logger.info(
            '{0} - Inserted data in DB'.format(
                self.pcap_filename,
        ))
        """
                
        # Download as many malware files as possible        
        self.logger.info('Now downloading malware for file {0}'.format(self.pcap_filename))
        try:
            for each in self.attack_attrib:
                if each['attack_info']:
                    id = outbound_conn_attempt_time.strftime("%Y_%m_%d_%H_%M_%S")
                    msg=[id, each['attack_info']]
                elif each['attack_data']:
                    id = outbound_conn_attempt_time.strftime("%Y_%m_%d_%H_%M_%S")
                    msg=[id, each['attack_data']]
                else:
                    continue
        
                address = (self.config['listener']['address'], self.config['listener']['port'])
                conn = Client(address, authkey=self.config['listener']['secret_key'])

                self.logger.debug(msg)                
                conn.send(msg)
                conn.close()
        
        except Exception as e:
            self.logger.debug(e)
        
        self.logger.info('Sent connection attempt info to downloader')
        self.logger.info('--------------- Finished processing file - {0} ---------------'.format(self.pcap_filename))

def main():    
    my_parser = PCAPParser()
    # [YLA] my_parser.detect_dns_queries()
    my_parser.detect_outbound_connections()

if __name__ == '__main__':
    main()
