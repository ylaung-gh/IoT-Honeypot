import glob
import logging.handlers
import os
import shutil
import subprocess
import time

from datetime import datetime
from peewee import IntegrityError
from settings import CONFIG

#from db_model import PcapJsonData

class PCAPConverter():
    def __init__(self):
        # Start by getting all the hardcoded config
        self.config = CONFIG
        # Check if log file exists. Create new file if it doesn't
        if not os.path.exists(self.config['pcap_to_json']['logfile']):
            open(self.config['pcap_to_json']['logfile'], "w").close()
        self.logger = logging.getLogger('converter')
        hdlr = logging.handlers.TimedRotatingFileHandler(
            self.config['pcap_to_json']['logfile'],
            when=self.config['pcap_to_json']['rotate_interval'],
            backupCount=self.config['pcap_to_json']['backup_count']
            )
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        hdlr.setFormatter(formatter)
        self.logger.addHandler(hdlr) 
        self.logger.setLevel(self.config['pcap_to_json']['log_level'])

        self.file_ctr = 0

    def convert(self):
        cur_time = time.time()
        # Subtract twenty minutes from current time as we won't process any current files
        self.logger.info("Will process files before {0}".format(
            datetime.fromtimestamp(float(time.time()-1200)).strftime('%Y-%m-%d %H:%M:%S')
        ))

        # Process 100 files at a time
        all_pcaps = list(glob.iglob(self.config['pcap_to_json']['orig_pcap_path'])) #converted into list to remove processed pcaps
        self.logger.info(f"All pcaps: {len(all_pcaps)}")
        #print(f"All pcaps: {len(all_pcaps)}")

        with open(self.config['pcap_to_json']['processed_pcaps_list'], "r") as infile:
            processed_files = set(map(lambda x: x.strip(), infile.readlines()))
        self.logger.info(f"Processed files: {len(processed_files)}")
        #print(f"Processed files: {len(processed_files)}")

        pcaps_for_processing = set()
        for pcap in all_pcaps:
            if pcap not in processed_files:
                #all_pcaps.remove(pcap)
                pcaps_for_processing.add(pcap)
        self.logger.info(f"Remaining files: {len(pcaps_for_processing)}")
        #print(f"Remaining files: {len(pcaps_for_processing)}")

        #for each_pcap in all_pcaps:
        for each_pcap in pcaps_for_processing:
            self.logger.info("Processing file #{0}".format(self.file_ctr))
            file_path, file_name = os.path.split(each_pcap)
            time_duration_to_skip = 1200            
            json_file_name = file_name.replace('pcap','json')
            json_file_path = file_path.replace('honeypot-pcaps','honeypot-jsons')
           #json_file_path = file_path.replace('honeypot-pcaps','honeypot-jsons-elk')
            json_file = os.path.join(
                json_file_path, json_file_name
            )
            # Create individual directories inside 'jsons' for every wormhole IP
            try:
                os.makedirs(json_file_path)
            except os.error:
                # Dir already exists, so ignore
                pass
            # Get the time when the file was last modified
            last_mod_time = os.path.getmtime(each_pcap)
                                
            # Only use file if it was last modified more than 20 min ago
            # Anything newer might still be being written to
            if cur_time - last_mod_time > time_duration_to_skip:
                self.logger.info(
                    "Converting {0} to {1}".format(file_name, json_file_name)
                )
                with open(json_file, "w") as outfile:
                    subprocess.call(
                        ["tshark", "-T", "ek", "-J", self.config['pcap_to_json']['protocols_to_analyze'], "-r", each_pcap],
                        stdout=outfile
                    )
                #processed_files.append(each_pcap)
                processed_files.add(each_pcap)
            else:
                self.logger.info(
                    "Ignoring file {0} with last_mod_time <{1}>".format(
                        file_name,
                        datetime.fromtimestamp(float(last_mod_time)).strftime('%Y-%m-%d %H:%M:%S')
                    )
                )
            self.file_ctr = self.file_ctr + 1
            if self.file_ctr % 200 == 0: #changed to 200 for now
                break
                            
        # Need to move the files to ensure that processed files are not processed again
        # We do not move the files in the above 'for' loop to avoid unpredictable behavior
        # for each_pcap in processed_files:
        #     file_path, file_name = os.path.split(each_pcap)
        #     file_path = file_path.replace('honeypot-pcaps', 'processed-pcaps')
        #     dst_file = each_pcap.replace('honeypot-pcaps', 'processed-pcaps')
        #     self.logger.info("Moving {0} to {1}".format(file_name, dst_file))
        #     try:
        #         os.makedirs(file_path)
        #     except os.error:
        #         # Dir already exists, so ignore
        #         pass
        #     shutil.move(each_pcap,"{0}".format(dst_file))

        # Update the list of processed pcap files
        with open(self.config['pcap_to_json']['processed_pcaps_list'], "w") as outfile:
            for each_processed_file in processed_files:
                outfile.write(each_processed_file + "\n")



        # List all files before rsync runs - BEFORE
        # self.logger.info("Transferring JSON files using rsync")
        # a = glob.iglob(self.config['pcap_to_json']['json_path'])
        # list_json_files_before_transfer = []
        # for each in a:
        #     file_path, file_name = os.path.split(each)
        #     list_json_files_before_transfer.append(file_name)
        # with open("/var/log/rsync_log/rsync_output.log", "a") as outfile:
        #     subprocess.call(
        #         ["/usr/bin/rsync", "-azvr", "--progress", "--remove-source-files", "--exclude", "mirroring_port/", "/media/honeypot/431382e8-e800-44f7-b55d-76a2ec01c14a/honeypot2/shared_data/jsons/", "honeypot@192.168.3.31:/home/honeypot/jsons"],
        #         stdout=outfile
        #     )
        # List all files after rsync runs - AFTER
        # a = glob.iglob(self.config['pcap_to_json']['json_path'])
        # list_json_files_after_transfer = []
        # for each in a:
        #     file_path, file_name = os.path.split(each)
        #     list_json_files_after_transfer.append(file_name)
        # # (BEFORE - AFTER) will be the list of files transferred
        # json_files_sent = list(
        #     set(list_json_files_before_transfer) - set(list_json_files_after_transfer)
        #     )

        # Get list of remote files
        # out, err = subprocess.Popen(
        #     ['ssh',
        #      'honeypot@192.168.3.31',
        #      'ls -R /home/honeypot/*jsons'
        #     ],
        #     stdout=subprocess.PIPE,
        #     stderr=subprocess.PIPE
        # ).communicate()
        # list_remote_files = out.split("\n")
        
        # pcap_json_info = []
        # for each_pcap in processed_files:
        #     file_path, file_name = os.path.split(each_pcap)
        #     single_dict_item = {
        #         'orig_pcap_name': file_name[:-5], # remove the extension
        #         'converted_to_json': 0,
        #         'rsync_sent_from_src': 0,
        #         'rsync_rcvd_at_dest': 0
        #     }
        #     if file_name.replace('.pcap','.json') in list_json_files_before_transfer:
        #         single_dict_item['converted_to_json'] = 1
        #     if file_name.replace('.pcap','.json') in json_files_sent:
        #         single_dict_item['rsync_sent_from_src'] = 1
        #     if file_name.replace('.pcap','.json') in list_remote_files:
        #         single_dict_item['rsync_rcvd_at_dest'] = 1
        #     pcap_json_info.append(single_dict_item)

        # PcapJsonData.insert_many(pcap_json_info).execute()

def main():
    pcap_converter = PCAPConverter()
    pcap_converter.logger.info("=============Begin PCAP to JSON conversion============")
    pcap_converter.convert()
    pcap_converter.logger.info("=============End PCAP to JSON conversion============")
    
if __name__ == "__main__":
    main()
