# Jamf Pro CTL

Jamf Pro Module for managing the servers in and querying the database of a single, or multiple, Jamf Pro instance(s).

This project allows you to execute commands against Jamf Pro Servers as well as query (and decrypt) content from the Jamf Pro Database.  Several convenience methods are provided such as:  start, stop, restart, backup, download(file), upload (file), and update the (entire) Jamf Pro instance.  (Supports multi-server environments, SSH, and MySQL interactions.)

Obviously, you'll need access to your running Jamf Pro MySQL Database -- so either an on-prem instance or a copy of the database will be required.


# Using the Module

The module was written to allow it to be exported into another script or code base to allow easy access to the helper methods available within.

For example, for information that cannot be obtained from Jamf Pro, whether with built-in Advanced Search/Smart Group criteria or from the API, the information can be obtained via SQL queries.  So, this module can be imported into a script and used to query the database for specific information, parse the results, and then interact with the API to automate tasks.

The module includes logic to SSH into hosts when/if required (as specified in the configuration file).

A yaml formatted configuration file is required to load and utilize this module.  If one is not provided, it will look for the default file name ".jps_env.yaml" in the current users' home  directory and then the current directory.


# Setup

```shell

# Create a directory to clone project into
mkdir "JamfProCTL" && cd "JamfProCTL"

# Clone this repository
git clone https://github.com/MLBZ521/jamf_pro_ctl.git .

# Create a virtual environment
python3 -m venv .venv

# Activate the virtual environment
source .venv/bin/activate

# Install the required packages:
pip install -r ./requirements.txt

# Customize the jps_env_sample.yaml example file included in the project then move it to your `$HOME` directory.
mv .jps_env_sample.yaml $HOME/.jps_env.yaml
```

# Example usage



#### Upgrading a Jamf Pro instance

```python

from jamf_pro_ctl import JamfProCTL

# Initialize an Jamf Pro Server Environment (specifically the dev environment here)
jps = JamfProCTL(env="dev")

# Update all servers in the environment
jps.update(installer="~/Download/jamf-pro-installer-linux-10.45.0.zip", prompt_to_continue = True)
```

Interactive prompts & output:
```
[Verbose] Uploading the installer...
`jps-primary.server.org`:`jamf-pro-installer-linux-10.45.0.zip` | Progress:  100.00% 
Upload(s) complete!
`jps-2.server.org`:`jamf-pro-installer-linux-10.45.0.zip` | Progress:  100.00% 
Upload(s) complete!
`jps-3.server.org`:`jamf-pro-installer-linux-10.45.0.zip` | Progress:  100.00% 
Upload(s) complete!

Stop the JPS instance? [Yes|No] y

[Verbose] Stopping Jamf Pro...
[Verbose] Tunnel is not active
[Verbose] SSHing into host `jps-primary.server.org`...Connected!
[Verbose] Executing Command:  `sudo /usr/local/bin/jamf-pro server stop`

[Verbose] Stopping Jamf Pro...
[Verbose] Tunnel is not active
[Verbose] SSHing into host `jps-2.server.org`...Connected!
[Verbose] Executing Command:  `sudo /usr/local/bin/jamf-pro server stop`

[Verbose] Stopping Jamf Pro...
[Verbose] Tunnel is not active
[Verbose] SSHing into host `jps-3.server.org`...Connected!
[Verbose] Executing Command:  `sudo /usr/local/bin/jamf-pro server stop`

Backup Jamf Pro Database? [Yes|No] y

[Verbose] Backing up the Jamf Pro Database...
[Verbose] Tunnel is not active
[Verbose] SSHing into host `jps-database.server.org`...Connected!
[Verbose] Executing Command:  `sudo /usr/local/bin/jamf-pro database backup`
[Verbose] Backup successful!
Database backup file: /usr/local/jss/backups/database/2023-04-21-151826.sql.gz

Have snapshots been taken for virtual servers? [Yes|No] y

Update Primary JPS? [Yes|No] y

[Verbose] Installing the Jamf Pro update on jps-primary.server.org
[Verbose] Executing Command:  `[[ -d ./update ]] && rm -rf ./update && mkdir ./update`
[Verbose] Executing Command:  `mv ./jamf-pro-installer-linux-* ./update`
[Verbose] Executing Command:  `unzip ./update/jamf-pro-installer-linux-* -d ./update/`
[Verbose] Executing Command:  `sudo sh ./update/jamfproinstaller.run --quiet -- -d -y`

Update Secondary JPS(s)? [Yes|No] y

[Verbose] Installing the Jamf Pro update on jps-2.server.org
[Verbose] Executing Command:  `[[ -d ./update ]] && rm -rf ./update && mkdir ./update`
[Verbose] Executing Command:  `mv ./jamf-pro-installer-linux-* ./update`
[Verbose] Executing Command:  `unzip ./update/jamf-pro-installer-linux-* -d ./update/`
[Verbose] Executing Command:  `sudo sh ./update/jamfproinstaller.run --quiet -- -d -y`

[Verbose] Installing the Jamf Pro update on jps-3.server.org
[Verbose] Executing Command:  `[[ -d ./update ]] && rm -rf ./update && mkdir ./update`
[Verbose] Executing Command:  `mv ./jamf-pro-installer-linux-* ./update`
[Verbose] Executing Command:  `unzip ./update/jamf-pro-installer-linux-* -d ./update/`
[Verbose] Executing Command:  `sudo sh ./update/jamfproinstaller.run --quiet -- -d -y`

SSHClient closed!
SSHClient closed!
SSHClient closed!
SSHClient closed!
```

#### Interacting with the Jamf Pro database

```python
jps = jps_ctl.JamfPro(env="prod")

# Get devices with TikTok installed and the apps "Management Status"
devices_with_tiktok, query_meta_data = jps.database.sql.query('select mobile_device_id, management_status from mobile_device_installed_applications where mobile_device_application_detail_id in (select distinct id from mobile_device_application_details where name like "%TikTok%");', close_ssh=False)

# devices_with_tiktok will be a a list of dicts
# e.g. devices_with_tiktok[0] = {'mobile_device_id': 2618, 'management_status': 'Unmanaged'}
# query_meta_data will be a a dict
# e.g. {'rowcount': 24, 'column_names': ('mobile_device_id', 'management_status')}

# Get the DP where ID = 3 and print to stdout in the standard MySQL CLI table format
jps.query("distribution_points", record_filter = {"distribution_point_id": 3}, decrypt=True, out_as_table=True)

# Get the computer where ID = 1234 and store it, as a dict, in a variable
jps.query("computers", record_filter = {"computer_id": 12345})

# Dump all tables with encrypted fields to individual <table>.html files
jps.dump_encrypted_tables(out="~/jamf_pro_db_decrypt/decrypted_tables")

# It's also possible to provide an encrypted string directly to be decrypted
decrypted_string = jps.decrypt("<encrypted_string>")
```

#### Managing open SSH/Database connections 

```python
# Check open SSH/Database connections
jps.open_sessions()
[{'jps-primary.server.org': <jps_ctl.SSHClient object at 0x107986c80>}, {'jps-database.server.org': <jps_ctl.SSHClient object at 0x104b739d0>}, {'jps-2.server.org': <jps_ctl.SSHClient object at 0x107986f20>}, {'jps-database.server.org': <sshtunnel._ThreadingForwardServer object at 0x1092101f0>}, {'jps-database.server.org': <mysql.connector.connection.MySQLConnection object at 0x107f5be50>}]

# Close open SSH/Database connections
jps.close_sessions()
SSHClient closed!
SSHClient closed!
SSHClient closed!
Closed DB Connection!
Closed SSH Tunnel!
```

# Credit

This module was created based on my work from [jamf_pro_db_decrypt](https://github.com/MLBZ521/jamf_pro_db_decrypt) which, in turn, was based on the initial reverse engineering and code created by [dmaasland](https://github.com/dmaasland).

The module goes further than simply interacting with the Jamf Pro database server to make it easier to manage our JPS instances.
