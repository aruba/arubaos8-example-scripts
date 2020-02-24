#!/usr/bin/env python3
# ------------------------------------------------------------------------------
#
# Author: pmalviya@arubanetworks.com, Aruba Engineering Group
# Organization: Aruba, a Hewlett Packard Enterprise company
#
# Version: 2017.03
#
#
# Copyright (c) Hewlett Packard Enterprise Development LP
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.
#
# ------------------------------------------------------------------------------

import threading
import datetime
import utils
import requests
import logging
from tabulate import tabulate
import argparse
import os.path
import time
import sendMail

LOCK = threading.Lock()
COUNT = 3
user_email = []
from_email = ''
controllers = ''
final_result = []
cnfFile = 'mailConfig.conf'
port = ''
localtime = datetime.datetime.now().strftime("%m%d%Y_%H%M%S")
outfile = 'results' + localtime + '.log'
logfile = 'logfile' + localtime + '.log'
import pdb

# setting the logging level
logging.basicConfig(filename=logfile, level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(name)s %(message)s')
logger = logging.getLogger(__name__)


def connect():
    """
    This function is utilized to read controllers information from CSV file and start the Multi-threaded session
    """
    file_name = controllers

    '''-----------------------reading CSV file-----------------------'''
    with open(file_name, 'r') as csv_file:
        cx = csv_file.readlines()

    i = 0
    thread_array = []
    t = [None] * len(cx)
    for line in cx:
        line = line.strip()
        a = line.split(',')

        '''------------Initiating a thread for API session to each controller IP----------------'''
        thread_array.append(a[0])
        if len(a) == 4:
            t[i] = threading.Thread(target=exec_api, args=(a[0], a[1], a[2], a[3],))

        t[i].daemon = True
        t[i].start()

        time.sleep(0.5)
        i += 1

    count = 0
    for thread in t:
        thread.join()
        logging.info("Thread with ip - {} completed".format(thread_array[count]))
        count += 1


def validate_tunnel_ip(data):
    """
       This function is validates the tunnel configurations and check for any overlapping IP addresses
       Returns results for failed entries
    """
    tunnel_val = [["Node name", "Tunnel ID", "Validation", "Message"]]
    for k, val in data.items():
        found_src = 0
        found_dst = 0
        match_src = set()
        match_dst = set()
        logging.info("validating tunnel configuration {}".format(k))
        if len(val) == 0:
            logging.info("no tunnel configuration exist on node {}".format(k))
            return (tunnel_val)
        try:
            for entry in val:
                if 'source' in entry:
                    if entry['source'] != '':
                        if entry['source'] in match_src:
                            found_src += 1
                        else:
                            match_src.add(entry['source'])
                    else:
                        logging.critical(
                            "tunnel source not configuration for tunnel id {} node {}".format(entry['tunnel_id'], k))
                        tunnel_val.append([k, entry['tunnel_id'], 'Validation Fail', 'No source ip configured'])
                        continue
                if 'destination' in entry:
                    if entry['destination'] != '':

                        if entry['destination'] in match_dst:
                            found_dst += 1
                        else:
                            match_dst.add(entry['destination'])
                    else:
                        logging.critical(
                            "tunnel destination not configuration for tunnel id {} node {}".format(entry['tunnel_id'],
                                                                                                   k))
                        tunnel_val.append([k, entry['tunnel_id'], 'Validation Fail', 'No destination ip configured'])
                        continue

                if (found_dst > 0 and found_src > 0):
                    # Raise alarm that overlapping IP found
                    logging.critical("duplicate tunnel entry found node {} tunnel {}, source {}, destination {} "
                                     .format(k, entry['tunnel_id'], entry['source'], entry['destination']))
                    tunnel_val.append([k, entry['tunnel_id'], 'Validation Fail', 'Overlapping IP found'])
                    found_src, found_dst = 0, 0
                else:
                    tunnel_val.append([k, entry['tunnel_id'], 'Validation Pass', 'No overlapping IP found'])
        except Exception as e:
            logging.info("key not found", e)
            raise
        logging.info("tunnel validation complete for node {}".format(k))
    return (tunnel_val)


def validate_tunnel_grp(tunconf, tungrp):
    """
          This function is validates the tunnel configurations and checks for tunnel group to tunnel id mapping.
          Returns results for failed entries
     """
    tunnel_grp = [["Node name", "Tunnel ID", "Tunnel Grp", "Validation", "Message"]]
    for k, val in tunconf.items():
        for entry in val:
            if 'tunnel_id' in entry:
                found = 0
                for j in tungrp[k]:
                    if entry['tunnel_id'] in j['member']:
                        found += 1
                        tunnel_grp.append([k, entry['tunnel_id'], j['tunnel_group'], 'Pass', 'Found Tunnel Group'])

                if found == 0:
                    logging.critical(
                        "tunnel_id {} not mapped to any tunnel group on node {}".format(entry['tunnel_id'], k))
                    tunnel_grp.append([k, entry['tunnel_id'], 'Not Found', 'Fail', 'Tunnel Group Not Found'])

        logging.info("tunnel group validation complete for node {}".format(k))

    return (tunnel_grp)


def validate_tunnel_status(data):
    """
           This function validates the tunnel state and
           Returns results for failed entries

     """

    intf_state = [["Node IP", "Tunnel ID", "Admin Status", "Oper Status", "Validation", "Message"]]
    for k, val in data.items():
        logging.critical("Validating tunnel status on node {}".format(k))

        for entry in val:
            if 'tunnel_id' in entry:
                if entry['oper_state'] != 'up' and entry['admin_state'] == 'up':
                    logging.critical(
                        "tunnel_id {} operational status is not UP on node {}".format(entry['tunnel_id'], k))
                    intf_state.append([k, entry['tunnel_id'], entry['admin_state'], entry['oper_state'], 'Fail',
                                       'Tunnel status Down'])
                else:
                    intf_state.append(
                        [k, entry['tunnel_id'], entry['admin_state'], entry['oper_state'], 'Pass', 'Tunnel status UP'])
                    logging.info("tunnel_id {} operational status is UP on node {}".format(entry['tunnel_id'], k))

    logging.info("tunnel status validation complete for node {}".format(k))
    return intf_state


def find_up_mds(data):
    """ checks for all the UP state MDs and returns a list of MDs"""
    val = []
    for k in data.keys():
        if data[k][3] == 'up':
            val.append(k)
    return (val)


def parseEmailconf(filename):
    """
    This funtion parses all the email related configuration from the mailconfig file
    :return dictionary of email related configuration
    :param takes input mailConfig.conf
    """
    values = {}
    with open(filename, 'r') as fd:
        data = fd.readlines()

    ''' reach data from the file and parse to get email credentials and server settings'''
    for entry in data:
        entry = entry.strip('\r\n')
        tlst = entry.split('=')
        if 'TO_EMAIL' in entry:
            tolist = tlst[1].split(',')
            values.update({tlst[0]: tolist})
            '''pass the emails if comma seperated as list'''
        else:
            values.update({tlst[0]: tlst[1]})
    return (values)


def exec_api(ip_address, username, password, model_type=""):
    """
    This function will login into the controller via API and execute all the commands sequentially for all the IPs.

    :param ip_address: IP address of the controller
    :param username: Username of the controller
    :param password: password of the controller
    :param model_type: if the controller is MM/MD
    """

    try:

        if not os.path.isfile(outfile):
            # create result file
            fd = open(outfile, 'w')
            fd.close()
        con = utils.ConnectUtil(ip_address, username, password, port)
        if not con.api_login():
            raise ConnectionRefusedError

        model_type = model_type.strip('\r\n')
        if model_type == 'MM':
            ''' get all the MDs connect to the particular MM'''
            con.execute_command("show switches")
            controller_ids = con.ps.parse_show_switches()
            md_list = find_up_mds(controller_ids)
            ''' execute show configuration committed on all MDs'''
            if len(md_list) > 0:
                print('validating configuration on MDs connected to MM {}\n'.format(ip_address))

                for cntr in md_list:
                    cntr = cntr.strip('\r\n')
                    cmd = 'show configuration committed ' + cntr
                    con.execute_command(cmd)
                    ''' parse the tunnel configuration tunnel source and tunnel destination'''
                    tun_conf = con.ps.parse_show_config_tunnel(cntr)

                    ''' validate for overlapping src/dst IP'''
                    result1 = validate_tunnel_ip(tun_conf)
                    # final_result.append(result1)
                    '''parse the tunnel group configuration from show config'''
                    tun_grp = con.ps.parse_tunnel_group(cntr)
                    '''validate tunnel grp assigned to the tunnels on the node'''
                    result2 = validate_tunnel_grp(tun_conf, tun_grp)
                    #  final_result.append(result2)
                    ''' write results to the result file'''
                    fd = open(outfile, "a")
                    fd.write('\noverlapping ip tunnel validation result for node {} connected to MM {},\n'
                             .format(cntr, ip_address))
                    fd.write('+++++++++++++++++++++++++++++++++++++++++++++++++\n')
                    if (len(result1) > 1):
                        fd.write(tabulate(result1, headers="firstrow"))
                        fd.write('\n')
                    else:
                        fd.write('No tunnels found for node {}'.format(cntr))
                        fd.write('\n')

                    fd.write(
                        '\ntunnel group validation result for node {} connected to MM {} ,\n'.format(cntr, ip_address))
                    fd.write('+++++++++++++++++++++++++++++++++++++++++++++++++\n')

                    if (len(result2) > 1):
                        fd.write(tabulate(result2, headers='firstrow'))
                        fd.write('\n')
                    else:
                        fd.write('No tunnels found for node {}'.format(cntr))
                        fd.write('\n')

                    fd.close()

                    '''print results on the terminal'''
                    if verbose and len(result1) > 1 and len(result2) > 1:
                        print('overlapping ip tunnel validation result for node {} connected to MM {},\n'
                              .format(cntr, ip_address))
                        print(tabulate(result1, headers='firstrow', tablefmt="fancy_grid"))
                        print('\ntunnel group validation result for node {} connected to MM {} ,\n'.format(cntr,
                                                                                                           ip_address))
                        print(tabulate(result2, headers='firstrow', tablefmt="fancy_grid"))

        if model_type == 'MD':
            ## check tunnel status
            print('validating tunnel status on MD {}\n'.format(ip_address))
            cmd = 'show ip interface brief'
            con.execute_command(cmd)

            '''parse tunnel UP / down status from each of the MD'''
            intf_state = con.ps.parse_show_ip_interface(ip_address)

            ''' validate if tunnel status is UP or DOWN'''
            result3 = validate_tunnel_status(intf_state)
            fd = open(outfile, "a")
            '''write to file the results'''
            fd.write('\ntunnel status validation result for MD node {},\n'.format(ip_address))
            fd.write('+++++++++++++++++++++++++++++++++++++++++++++++++\n')
            if len(result3) == 1:
                logging.critical('NO Tunnels Found for MD node {}'.format(ip_address))
                fd.write('No Tunnels found for node {}\n'.format(ip_address))
                if verbose:
                    print('No Tunnels found for node {}.\n'.format(ip_address))
            else:
                ''' write results to the result file'''
                fd.write(tabulate(result3, headers="firstrow"))
                final_result.append(result3)
                fd.write('\n')
                '''print results on the terminal'''
                if verbose:
                    print('\ntunnel status validation result for MD node {},\n'.format(ip_address))
                    print(tabulate(result3, headers="firstrow", tablefmt="fancy_grid"))
            fd.close()
        con.handle.close()
    except ConnectionRefusedError as e:
        logging.critical("Unable to connect to Controller. Login Failed. {}".format(ip_address))
    except requests.RequestException as e:
        logging.critical("New Connection error. Network Failure {}".format(ip_address))
    except Exception as e:
        logging.critical("session timeout/ controller crashed {}".format(ip_address))


def main():
    connect()
    if os.path.isfile(cnfFile):
        ''' Parse the mailConfig.conf file to get all the email related parameters'''
        eml = parseEmailconf(cnfFile)
        user_email = eml['TO_EMAIL']
        from_email = eml['FROM_EMAIL']
        server = eml['MAIL_SERVER']
        port = eml['PORT']
        password = eml['PASSWORD']
        with open(outfile, 'r') as fd:
            filecontent = fd.read()
        print('trying to send email\n')
        sendMail.send_email(user_email, from_email, password, server, port, filecontent, [outfile, logfile])
        print('completed config validation\ncheck results file {} and logfile {} for more details'.format(outfile,
                                                                                                          logfile))
        logging.info(
            'completed config validation\ncheck results file {} and logfile {} for more details'.format(outfile,
                                                                                                        logfile))


if __name__ == "__main__":
    parser = argparse.ArgumentParser('Run Tunnel Validation  tool.\n'
                                     'Example: mainFile.py  --controller controllers.txt --port 4343 --verbose\n')

    parser.add_argument('--controllers', help='list of controllers and username/password, \n'
                                              'Default file is included with distribution, \n'
                                              'Example - 10.1.1.1,viewonly,viewonly,MD')
    parser.add_argument('--port', default=443, help='provide custom REST API https port, default port used is 443')
    parser.add_argument('--verbose', dest='verbose', action='store_true', help='set this option to print results on '
                                                                               'terminal\n')
    parser.set_defaults(verbose=False)

    args = parser.parse_args()
    if args.controllers is None:
        print("**********************************************\n"
              "Sorry. This tool requires a file with all the \n"
              "controllers IP ,username,passwrd listed.\n"
              "Provide these details as command-line arguments\n"
              "Use --help for usage example.\n"
              "**********************************************")
        exit()

    else:
        controllers = args.controllers

    port = args.port
    verbose = args.verbose
    main()
