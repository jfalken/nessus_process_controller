# Nessus Process Controller

## What is this

1. Enumerate your public AWS Assets (e.g., instances, RDS-instances, load-balancers).

2. Take the above info and launch a scan in Tenable's Cloud Scanner service.

3. Periodically check the status of the scan, when its done it will download the results in XML, HTML and JSON formats.

The application uses MongoDB locally. This is used to store the output of the scans (gridfs is used to store the XML, HTML files, etc). MongoDB is also used to maintain state of each scan.

## Configuration

1. Edit the config file in `config/config.yaml`.

Under `nessus`, set your username and password for the Tenable Service. (you must have a paid account for this service).

Under `aws_accounts`, for each AWS account you have, you must list the AWS Access key ID under `key`, and the AWS Secret Key ID under `secret`. Also give each account a `name`, so it can be identified in the logs and reports. If you have only one account, remove the second account example.

2. `pip install -r requirements` to install all requirements.

3. Install MongoDB locally. Bind to localhost

## Usage

`./nessus_process_controller.py -c config`

You should cron this to run every few minutes. We cron it to run every 3 minutes. There is a built in locking mechanism so if a new job kicks off while an old process is running, its ok.

### Help

```
usage: nessus_process_controller.py [-h] -c CONFIG
nessus_process_controller.py: error: argument -c/--config is required
```


## Why?

We wanted a reliable way to ensure scans we want periodically run were actually being run, and we get the results in our own system, so we can parse the XMLs for our own needs and have HTMLs ready for quick viewing. 




