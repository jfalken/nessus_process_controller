#!/usr/bin/env python
'''
    This script queries Amazon AWS accounts for public IP addresses
    and and launches Nessus Scans with this IP information.
    Scan ID information is tracked in MongoDB.
    This information is used to kickoff new scans after a determined amount of time
    and to download prior reports.
'''

import sys
import yaml
import logging
import argparse
from libs import NessusClient as NessusClient
from datetime import datetime
from libs.utils import check_lock_status
from libs.utils import enable_lock
from libs.utils import disable_lock
from libs.utils import read_aws_scan_records
from libs.utils import read_misc_scan_records
from libs.utils import create_mdb_record
from libs.utils import account_in_mdb
from libs.utils import get_aws_creds
from libs.utils import get_aws_public_ips
from libs.utils import get_rds_hostnames
from libs.utils import upsert_mdb_record
from libs.utils import get_mdb_record_status
from libs.utils import insert_file_gridfs
from libs.utils import insert_scan_details
from libs.utils import ensure_details_index
from libs.utils import get_vuln_summary_from_hosts


# if you want to use a proxy, also set proxies=proxies when for nrc obj
# proxies = {
#   "http": "http://127.0.0.1:8080",
#   "https": "http://127.0.0.1:8080",
# }


def setup_logging(config):

    logging.basicConfig(filename=config['log']['file'],
                        format=config['log']['format'],
                        datefmt=config['log']['dateformat'],
                        level=logging.INFO)
    logging.getLogger('requests').propagate = False

    return logging


def main(config):
    ''' main script '''
    try:
        logging = setup_logging(config)

        logging.info('[NPC] Started.')

        # Check for a lock (other service is running?)
        lock_status = check_lock_status()
        if lock_status == 'locked':
            logging.info('[NPC] Lock in Place. Quitting')
            sys.exit(0)

        if lock_status != 'not_locked':
            logging.error('[NPC] Invalid Lock Status, Quitting')
            sys.exit(1)

        # Enable the lock and Read MongoDB Scan Status
        enable_lock()

        # Create NessusRestClient
        server = 'https://' + config['nessus']['server']
        port = config['nessus']['port']
        username = config['nessus']['username']
        password = config['nessus']['password']
        nrc = NessusClient.NessusRestClient(server=server,
                                            port=port,
                                            username=username,
                                            password=password)

        aws_scans = read_aws_scan_records()
        logging.info('[NPC] Found %s AWS scan records' % str(len(aws_scans)))
        misc_scans = read_misc_scan_records()
        logging.info('[NPC] Found %s schedule Nessus scan records' % str(len(misc_scans)))
        scans = aws_scans + misc_scans

        # Iterate through AWS Accounts in config file;
        # If mongodb scan record doesnt exist; create one
        for account in config['aws_accounts']:
            if not account_in_mdb(account['name'], 'aws_scan_record'):
                create_mdb_record(account['name'], 'aws_scan_record')
                logging.info('[NPC] %s was not in MongoDB. Creating.' % account['name'])

        # check the Nessus folders; ensure 'AWS' and 'Non-AWS' exists
        # if not, create them
        for f in ['AWS', 'Non-AWS']:
            folder = nrc.get_folder_by_name(f)
            if not folder:
                fid = nrc.create_folder(f)
                logging.info('[NPC] Created folder "%s", id "%s"' % (f, str(fid)))

        aws_f_id = nrc.get_folder_by_name('AWS')['id']
        non_aws_f_id = nrc.get_folder_by_name('Non-AWS')['id']

        # Iterate through the Non-AWS scans in Nessus;
        # These scans must be created manually. this process only launches/downloads
        # If mongodb scan record doesnt exist; create one
        for non_aws_scan in nrc.get_scans(folder_id=non_aws_f_id):
            if not account_in_mdb(non_aws_scan['name'], 'misc_scan_record'):
                create_mdb_record(non_aws_scan['name'], 'misc_scan_record')
                logging.info('[NPC] %s was not in MongoDB. Creating.' % non_aws_scan['name'])

    except SystemExit:
        sys.exit()
    except:
        print 'Error during init: %s' % str(sys.exc_info())
        try:
            disable_lock()
        except:
            pass
        sys.exit(1)

    # Iterate through all the scan status records in MDB
    for s in scans:
        try:
            account_name = s['aws_account']
            record_type = s['type']
            logging.info('[NPC] Starting process for %s' % account_name)
            if s['scan_status'] in ['pending','running','launched','processing']:
                logging.info('[NPC] Current status: "%s". Updating Status' % s['scan_status'])
                # Get current MDB Record
                mdb_record = get_mdb_record_status(account_name, record_type)
                # Get the Status from Nessus
                scan_id = mdb_record['current_scan_id']
                scan_info = nrc.get_scan_details(scan_id=scan_id)['info']
                status = scan_info['status']
                # Update the record; mix of nessus status and old record
                r = upsert_mdb_record(account_name = account_name,
                                      scan_launch_date = mdb_record['last_scan_launched'],
                                      scan_status = status,
                                      scan_id = scan_id,
                                      record_type = record_type)
                logging.info('[NPC] Status Updated to "%s"' % status)
                continue
            elif s['scan_status'] == 'completed':
                logging.info('[NPC] Current status: "complete". Proceeding to DL.')
                # Download the thing
                mdb_record = get_mdb_record_status(account_name, record_type)
                scan_id = mdb_record['current_scan_id']
                launch_date = mdb_record['last_scan_launched']
                upload_date = datetime.utcnow()
                # XML File
                logging.info('[NPC] Attempting XML download.')
                # Tenable tends to fail here randomly. Future script runs will
                # catch this, but this is also quicker
                try:
                    contents = nrc.download_report(scan_id=scan_id, format='xml')
                except:
                    logging.error('[NPC] Could not download XML report; will try later -> %s' % str(sys.exc_info()))
                    continue
                # Insert Contents to MongoDB
                filename = '%s Scan - %s' % (account_name, str(launch_date))
                oid = insert_file_gridfs(contents=contents, gridfsdb='xmlfiles',
                                         filename=filename, uuid=scan_id,
                                         report_date=launch_date,
                                         upload_date=upload_date,
                                         account=account_name)
                logging.info('[NPC] XML Report added: %s' % str(oid))

                # HTML File
                logging.info('[NPC] Attempting HTML download.')
                # same as above for XML
                try:
                    contents = nrc.download_report(scan_id=scan_id, format='html')
                except:
                    logging.error('[NPC] Could not download HTML report; will try later -> %s' % str(sys.exc_info()))
                    continue
                # Insert Contents to MongoDB
                filename = '%s Scan - %s' % (account_name, str(launch_date))
                oid = insert_file_gridfs(contents=contents, gridfsdb='htmlfiles',
                                         filename=filename, uuid=scan_id,
                                         report_date=launch_date,
                                         upload_date=upload_date,
                                         account=account_name)
                logging.info('[NPC] HTML Report added: %s' % str(oid))

                # Get and insert the JSON Results
                logging.info('[NPC] Attempting JSON Results/Details download.')
                try:
                    details = nrc.get_scan_details(scan_id=scan_id)
                except:
                    logging.error('[NPC] Could not obtain scan details. Wil try later -> %s' % str(sys.exc_info()))
                    continue

                td = {}
                td['info'] = details['info']
                td['rem'] = details['remediations']
                td['vulns'] = details['vulnerabilities']
                td['hosts'] = details['hosts']
                td['source'] = account_name
                td['scan_id'] = scan_id
                td['filename'] = filename
                td['report_date'] = launch_date
                td['upload_date'] = upload_date
                td['vuln_summary'] = get_vuln_summary_from_hosts(td['hosts'])
                try:
                    r = insert_scan_details(td)
                    logging.info('[NPC] JSON details added: %s' % str(r))
                except:
                    logging.error('[NPC] Could not insert scan details into mongodb. Will try later -> %s' % str(sys.exc_info()))
                    continue

                try:
                    ensure_details_index()
                except:
                    logging.error('[NPC] Issue ensuring index: %s' % str(sys.exc_info()))

                # update MDB scan status record since we're done
                r = upsert_mdb_record(account_name = account_name,
                                      scan_launch_date = launch_date,
                                      scan_status = 'downloaded',
                                      scan_id = scan_id,
                                      record_type = record_type)
                logging.info('[NPC] MDB Scan Record updated: %s' % str(r))

            elif s['scan_status'] == 'downloaded':
                logging.info('[NPC] Checking scan time delta.')
                mdb_record = get_mdb_record_status(account_name, record_type)
                last_scan_time = mdb_record['last_scan_launched']
                time_now = datetime.utcnow()
                timedelta = time_now - last_scan_time
                tds = timedelta.total_seconds()  # this requires python27
                if tds > (60 * 60 * 12):
                    logging.info('[NPC] Timedlta is %s seconds. Will launch next run.' % str(tds))
                    r = upsert_mdb_record(account_name = account_name,
                                          scan_launch_date = last_scan_time,
                                          scan_status = None,
                                          scan_id = None,
                                          record_type = record_type)
                    continue
                logging.info('[NPC] Timedlta is %s seconds. Skipping.' % str(tds))

            elif s['scan_status'] is None:
                logging.info('[NPC] Launching a new scan.')
                dt = datetime.utcnow()

                ## Launch a new scan
                if record_type == 'aws_scan_record':
                    # Enumerate AWS IPs
                    try:
                        key, secret = get_aws_creds(account=account_name,
                                                    config=config)
                        targets = get_aws_public_ips(key=key,
                                                     secret=secret)
                        logging.info('[NPC] Obtained %s IPs' % len(targets))
                    except:
                        logging.error('[NPC] Could not obtain credentials')
                        continue
                    # Enumerate RDS
                    try:
                        rds_instances = get_rds_hostnames(key, secret)
                    except:
                        logging.error('[NPC] Error enumerating RDS instances: %s' % str(sys.exc_info()))
                        rds_instances = []

                    # concat instance IPs + RDS hostnames
                    targets = targets + rds_instances

                    if len(targets) == 0:
                        logging.info('No targets, adding 127.0.0.1 as placeholder')
                        targets = ['no.hosts.were.found.local.10gen.com']

                    # Send report summary to these email(s)
                    emails = ['youremail@yourdomain.xyz']

                    # Get Scan object_id
                    policy = nrc.get_scan_policy_by_name('Perimeter Scan (exhaustive)')  # must already exist
                    policy_uuid = policy['template_uuid']

                    # Create a new scan
                    scan_name = '%s Scan - %s UTC' % (account_name, str(dt))
                    settings = nrc.get_settings_dict(policy_uuid = policy_uuid,
                                                     scan_name = scan_name,
                                                     description = 'NPC Scan',
                                                     emails = emails,
                                                     targets = targets,
                                                     folder_id = aws_f_id)
                    resp = nrc.create_scan(settings)
                    scan_id = resp['id']

                    # Launch the scan
                    nrc.launch_scan(scan_id)
                    logging.info('[NPC] Scan launched')

                elif record_type == 'misc_scan_record':
                    try:
                        # get the scan info from Nessus
                        # This is based off matching names
                        scan_info = None
                        for non_aws_scan in nrc.get_scans(folder_id=non_aws_f_id):
                            if non_aws_scan['name'] == account_name:
                                scan_info = non_aws_scan
                        if not scan_info:
                            logging.error('[NPC] Could not find scan info for "%s"' % account_name)
                            raise Exception('Could not find scan info')

                        scan_id = scan_info['id']
                        logging.info('[NPC] Scan ID is %s' % str(scan_id))

                        # id has been obtained, launch the scan
                        nrc.launch_scan(scan_id)
                        logging.info('[NPC] Scan launched')
                    except:
                        logging.error('[NPC Failed to launch sched scan. "%s"' % str(sys.exc_info()))
                        continue

                # update MDB scan status record
                r = upsert_mdb_record(account_name = account_name,
                                      scan_launch_date = dt,
                                      scan_status = 'launched',
                                      scan_id = scan_id,
                                      record_type = record_type)
                logging.info('[NPC] MDB Scan Record updated: %s' % str(r))

            else:
                logging.error('[NPC] Unknown scan status "%s", restarting.' % s['scan_status'])
                r = upsert_mdb_record(account_name = account_name,
                                      scan_launch_date = None,
                                      scan_status = None,
                                      scan_id = None,
                                      record_type = record_type)
                disable_lock()

        except:
            logging.error('[NPC] Unknown error: %s' % str(sys.exc_info()))
            disable_lock()
            logging.info('[NPC] Lock released.')
            try:
                nrc.logout()
            except:
                pass
            sys.exit(1)

    # Done iterating through scans, release lock and exit
    logging.info('[NPC] Done iterating through all AWS accounts.')
    disable_lock()
    logging.info('[NPC] Lock released.')
    nrc.logout()
    sys.exit(0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='''This script queries Amazon AWS
    accounts for public IP addresses and updates existing Nessus scan templates with
    those IP addresses. See Github documentation for further details.''')

    parser.add_argument('-c', '--config', dest='config', required=True,
                        help='(Required) YAML configuration file')
    args = parser.parse_args()

    # Load config params
    try:
        config = yaml.load(open(args.config,'r').read())
    except:
        print '[NPC] Error: could not load the config file --> "%s"' % str(sys.exc_info()[1])
        sys.exit(1)

    main(config=config)

