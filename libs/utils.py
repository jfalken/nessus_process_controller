import sys
import logging
import boto
import boto.rds
import gridfs
from pymongo import MongoClient
from datetime import datetime

def _mongo_connect():
    ''' connects to mongodb and returns a col obj '''
    try:
        return MongoClient()['nessus']['aws_scan_tracking']
    except:
        logging.error('[NesUpdateLaunch] Couldnt connect to MongoDB. Quitting')
        raise


def check_lock_status():
    ''' returns status of lock; creates lock record 
        if it does not already exist
    '''
    col = _mongo_connect()
    doc = col.find({'type':'lock'})
    # If we dont have a lock document; create one
    if doc.count() == 0:
        col.update({'type': 'lock'},
                   {'type': 'lock',
                    'status': 'not_locked'},
                    upsert=True)
        return 'not_locked'
    else:
        return doc[0]['status']


def enable_lock():
    ''' enabled service lock '''
    col = _mongo_connect()
    doc = col.find({'type':'lock'})
    col.update({'type': 'lock'},
               {'type': 'lock',
                'status': 'locked'},
                upsert=True)
    return


def disable_lock():
    ''' disables service lock '''
    col = _mongo_connect()
    doc = col.find({'type':'lock'})
    col.update({'type': 'lock'},
               {'type': 'lock',
                'status': 'not_locked'},
                upsert=True)
    return


def read_aws_scan_records():
    ''' reads all aws scan records from mdb and returns a list of dicts '''
    col = _mongo_connect()
    docs = col.find({'type':'aws_scan_record'})
    return [i for i in docs]


def read_misc_scan_records():
    ''' reads all schedule scan records from mdb and returns a list of dicts '''
    col = _mongo_connect()
    docs = col.find({'type':'misc_scan_record'})
    return [i for i in docs]


def account_in_mdb(account_name, record_type):
    ''' checks if account_name has a aws_scan_tracking record
        returns Boolean
    '''
    col = _mongo_connect()
    c = col.find({'type' : record_type,
                  'aws_account' : account_name})
    if c.count() == 0:
        return False
    elif c.count() == 1:
        return True
    else:
        logging.error('[NesUpdateLaunch] Error determinig accounts in mongodb - %s' % str(sys.exc_info()))
        return False


def create_mdb_record(account_name, record_type):
    ''' creates and inits an aws_scan_tracking record for account_name
        returns objectid
    '''
    col = _mongo_connect()
    oid = col.insert({'type' : record_type,
                      'aws_account': str(account_name),
                      'last_scan_launched' : None,
                      'scan_status' : None,
                      'current_scan_id' : None })
    return oid


def upsert_mdb_record(account_name,
                      scan_launch_date,
                      scan_status,
                      scan_id,
                      record_type):
    ''' creates and inits an aws_scan_tracking record for account_name 
        'scan_launch_date' must be a datetime object
        'scan_status' must be a valid status
        returns objectid
    '''
    col = _mongo_connect()
    oid = col.update({'type' : record_type,
                      'aws_account': str(account_name)},
                     {'type' : record_type,
                      'aws_account': str(account_name),
                      'last_scan_launched' : scan_launch_date,
                      'scan_status' : scan_status,
                      'current_scan_id' : scan_id },
                      upsert=True)
    return oid


def get_mdb_record_status(account_name, record_type):
    ''' creates and inits an aws_scan_tracking record for account_name
        returns objectid
    '''
    col = _mongo_connect()
    c = col.find({'type' : record_type,
                  'aws_account': str(account_name)})
    return c[0]


def get_aws_creds(account, config):
    ''' return (key, secret) for account from config '''
    for a in config['aws_accounts']:
        if a['name'] == account:
            key = a['key']
            secret = a['secret']
            return key, secret
    logging.error('Could not find creds for %s' % account)
    raise Exception('could not obtain credentials')


def get_aws_public_ips(key, secret):
    ''' returns public ip addresses for all instances in all
        regions for this account
    '''
    ec2s = []
    public_ips = []

    ec2 = boto.connect_ec2(key, secret)
    regions = ec2.get_all_regions()
    for region in regions:
        ec2 = region.connect(aws_access_key_id=key,
                             aws_secret_access_key=secret)
        ec2s.append(ec2)

    res_list = []
    for ec2 in ec2s:
        reservations = ec2.get_all_reservations()
        for reservation in reservations:
            res_list.append(reservation)
    instances = [i for r in res_list for i in r.instances]
    for instance in instances:
        if instance.ip_address == None: continue
        public_ips.append(instance.ip_address)

    return public_ips


def get_rds_hostnames(key, secret):
    ''' returns public hostnames for rds instances '''
    hosts = []

    ec2 = boto.connect_ec2(key, secret)
    regions = ec2.get_all_regions()
    regions = [i.name for i in regions]

    for region in regions:
        rds = boto.rds.connect_to_region(region,
                                         aws_access_key_id=key,
                                         aws_secret_access_key=secret)
        rds_instances = rds.get_all_dbinstances()
        for i in rds_instances:
            hostname = i.endpoint[0]
            port = i.endpoint[1]
            hosts.append(hostname)

    return hosts


def insert_file_gridfs(contents, gridfsdb, filename, uuid, 
                       report_date, upload_date, account):
    ''' inserts a file into mongodbgridfs '''
    assert gridfsdb in ['htmlfiles','xmlfiles']
    client = MongoClient('localhost', 27017)
    db = client[gridfsdb]
    fs = gridfs.GridFS(db)
    oid = fs.put(data        = contents,
                 account     = account,
                 filename    = filename,
                 uuid        = str(uuid),
                 report_date = report_date,
                 upload_date = upload_date)
    return oid


def insert_scan_details(document):
    ''' inserts document into the nessus scan details collection '''
    client = MongoClient()
    col = client['nessus']['details']
    return col.insert(document)


def ensure_details_index():
    ''' runs an ensure index on the details collection for
        things we care about
    '''
    client = MongoClient()
    col = client['nessus']['details']
    col.ensure_index('source')
    col.ensure_index('info.timestamp')
    col.ensure_index('hosts.hostname')
    return


def get_vuln_summary_from_hosts(hosts):
    ''' given a list of hosts (from get_scan_details); summarize
        the count of vulnerabilities and return that dict
    '''
    d = {}
    levels = ['info', 'low', 'medium', 'high', 'critical']
    for l in levels:
        d[l] = 0
    for h in hosts:
        for l in levels:
            try:
                d[l] += h[l]
            except:
                pass
    return d
