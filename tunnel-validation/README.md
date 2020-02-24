# tunnel-validation

## Requirements

- Remote server (preferably unix) with access to controllers (MM/MD) 
- Python version 3 installed on the server
- Utilizes REST APIs for controller communication, HTTS traffic allowed to controllers in the network.
- Valid SMTP server url and port, email address for generating email with results/alert (optional if email alerts is needed)
- Valid internet connection on the server (where the script will be hosted) for Python libraries to be installed.

## Script Usage instructions

1. Clone the repository arubaos8-example-scripts
2. `cd tunnel-validation`
3.  Install all the dependencies from requirements.txt 
    `pip3 install -r requirements.txt`

4. Modify the mailConfig.conf file with relevant details. Sample file included.
```
MAIL_SERVER=<server address here> eg smtp.gmail.com
PORT=<port> eg 587
TO_EMAIL=<comma separated emails> eg. abc@hotmail.com, xyz@gmail.com
FROM_EMAIL=<email address for FROM field> noc@network.com
PASSWORD= <email passwd for user ‘from_email’>
```

5. Add controller information to the controllers.txt file. Sample file included.
```
<ip address,username,password,MM/MD>
If ip address signifies MM use keyword ‘MM’ else use MD 

10.162.236.101,viewonly,aruba123,MM
10.163.140.253,viewonly,aruba123,MD
```

6. Run the script 

`python3 mainFile.py --port 4343  --controllers controllers.txt --verbose`
 
### Help 

```
$ python3 mainFile.py --help
usage: Run Tunnel Validation  tool.
Example: mainFile.py  --controller controllers.txt --port 4343 --verbose

       [-h] [--controllers CONTROLLERS] [--port PORT] [--verbose]

optional arguments:
  -h, --help            show this help message and exit
  --controllers CONTROLLERS
                        list of controllers and username/password, Default
                        file is included with distribution, Example -
                        10.1.1.1,viewonly,viewonly,MD
  --port PORT           provide custom REST API https port, default port used
                        is 443
  --verbose             set this option to print results on terminal 
  
  ```
  


### Tool Description and Scope

Tool validated GRE (IPV4) tunnels and generates error logs/email.
•	Validate if the tunnel provisioned has any overlapping IP addresses with other tunnels on same node.
•	Validate if the tunnel is part of any tunnel-group or not
•	Generate logs and script audit trail to files with current run information and results.
•	Optionally can generate email if access to SMTP server is provided.

Script utilizes REST APIs module to collect the necessary information from the devices and these needs to be allowed/reachable from the server the script would be executed from. Script runs 1 time and exits printing the logs and results into respective files/terminals. Script only needs 'ready only' access to the controllers.

### Funtional Module

#### Input

- Takes list of controllers as input, where the validation needs to happen. The list of controllers to be specified in the file in below format:
```
<ipaddress>,<username>,<password>,<MM or MD>
10.1.1.1,viewonly,viewonly,MM
139.1.1.10,viewonly,passwd,MD
```
  
Note: MD/MM IP-addresses mentioned need to be reachable from the server script is hosted. READ-ONLY access is needed to the controllers. 

#### Connection

- Script reads the <input file> and establishes a connection to each of the IP address and takes action based on the role assigned i.e MM or MD
- Script utilizes REST APIs to connect to these controllers and does them in multithreaded way.
- If the entry from the file is MM : below is done;
    1. Logs into MM and gets all the names of MDs in UP state
    2. Collects RUN configurations from each of the MDs.
    3. Parses Tunnel-configuration and passes to Validation module.
- If the entry from the file is MD : below is done:
    1. Logs into MD and validates tunnel status

#### Validation

- Checks every MD connected to that MM, if any Tunnel ID has overlapping IP with another tunnel id on same node.
- Checks every MD connected to that MM, if any Tunnel ID is not part of existing tunnel-groups.
- Does a check on MD – and validates the status of Tunnel interfaces.

#### Output/Alerting
- Script logs all run information – in a logfile
- Result available as; 
    - printed on the terminal
    - dumped output file 
    - Emailed

