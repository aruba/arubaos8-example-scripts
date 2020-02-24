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

import re
import requests
import urllib3
import json
import datetime
import pdb

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROMPT = re.compile(r"([a-zA-Z0-9\-.\s]*#)")

headers = {
    "Content-Type": "application/json",
    "Accept": "application/json"
}


class ConnectUtil:

    def __init__(self, ip, user='', password='', port=443):
        self.ip = ip
        self.port = port
        self.user = user
        self.password = password
        self.handle = None
        self.ps = ParseCommand()
        #        self.val_obj = validation.Validation()
        self.output = ''

    def api_login(self) -> object:
        """
        This function will login into the controller using API.

        :return: connection handle for the device.

        """
        username = self.user.replace('\n', '')
        password = self.password.replace('\n', '')
        value = "uid=" + username + "&passwd=" + password

        try:
            if self.ip:
                r = requests.post('https://{}:{}/screens/wms/wms.login'.format(self.ip, self.port), data=value,
                                  verify=False)
                #  print("Connected to {} - {}".format(self.ip, r))
                self.handle = r
                return True
            else:
                raise Exception("No IP")
        except Exception as err:
            # print("Failed to connect to {}\n\nError: {}".format(self.ip, err))
            return False

    def execute_command(self, cmd: str) -> object:
        """

        This function will execute commands on controller and returns the output

        :param cmd: command to be executed on device
        :return: data containing output of the command

        """
        parameters = {"UIDARUBA": self.handle.headers['Set-Cookie'].split(';')[0].split('=')[1], "command": cmd}
        self.handle = requests.get('https://{}:4343/v1/configuration/showcommand'.format(self.ip), verify=False,
                                   headers=headers,
                                   params=parameters, cookies=self.handle.cookies)
        data = self.handle.content.decode('utf-8')
        self.ps.value = data
        self.output = data


class ParseCommand:

    def __init__(self, value='', sc_model=''):
        self.value = value
        self.sc_model = sc_model

    def parse_show_switches(self):
        """
        Parses show switches output
        :returns dictionary with Node Name , IP address, Configuration Status and Status of MD

        """
        localtime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data = json.loads(self.value)
        new_values = {}
        for var in data['All Switches']:
            if var['Type'] == 'MD':
                attribute_name = var['Name']
                tupple = (localtime, var['IP Address'], var['Configuration State'], var['Status'])
                new_values.update({attribute_name.rstrip(): tupple})
        return new_values

    def parse_show_config_tunnel(self, node):
        """
        Parses whole configuration and looks for GRE tunnel configuration
        :returns dictionary with Node Name , attributes; tunnel intf, src IP, dst IP

        """
        data = json.loads(self.value)
        tun = []
        val_list = data['_data'][0].split('!')
        tun_id = ''
        src_ip = ''
        dst_ip = ''
       # pdb.set_trace()
        for entry in val_list:
            if re.search('interface\s+tunnel\s+\d+', entry):
                #  pdb.set_trace()
                m = re.search('interface\s+tunnel\s+(\d+)', entry)
                if m:
                    tun_id = m.group(1)
                m = re.search('source\s+(\d+\.\d+\.\d+\.\d+)', entry)
                if m:
                    src_ip = m.group(1)
                else:
                    src_ip = ''
                m = re.search('destination\s+(\d+\.\d+\.\d+\.\d+)', entry)
                if m:
                    dst_ip = m.group(1)
                else:
                    dst_ip = ''
                val_dict = {'tunnel_id': tun_id, 'source': src_ip, 'destination': dst_ip}
                tun.append(val_dict)

        retval = {node: tun}
        return retval

    def parse_tunnel_group(self, node):
        """
            Parses whole configuration and looks for GRE tunnel group configuration
            :returns dictionary with Node Name , attributes; tunnel group name and members

        """
        data = json.loads(self.value)
        tun = []
        val_list = data['_data'][0].split('!')
        grp_name = ''
        member = []
        for entry in val_list:
            if re.search('tunnel-group', entry):
                m = re.search('tunnel-group\s+(.+)\s+', entry)
                if m:
                    grp_name = m.group(1)
                m = re.findall('tunnel\s+(\d+)', entry)
                if len(m) > 0:
                    member = m
                val_dict = {'tunnel_group': grp_name, 'member': member}
                tun.append(val_dict)
        retval = {node: tun}
        return retval

    def parse_show_ip_interface(self, node):
        """
            Parses whole configuration and looks for GRE tunnel group configuration
            :returns dictionary with Node Name , attributes; ip address/subnet, admin state and Oper state group name and members

        """
        data = json.loads(self.value)
        tun = []

        for entry in data['_data']:
            if re.search('tunnel', entry):
                m = re.search('tunnel\s+(\d+)\s+(.+?)\s+\/\s+(.+?)\s+(.+?)\s+(.+)', entry)
                if len(m.groups()) > 4:
                    tun_id = m.group(1)
                    ip = m.group(2)
                    subnet = m.group(3)
                    admin_state = m.group(4)
                    oper_state = m.group(5)
                    val_dict = {'tunnel_id': tun_id, 'ip': ip, 'subnet': subnet, 'admin_state': admin_state,
                                'oper_state': oper_state}
                    tun.append(val_dict)
        retval = {node: tun}
        return retval
