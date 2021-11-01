# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0

import logging, re
from typing import List
import http.client
import requests
import json
import time

from blockcypher import get_address_overview
from requests.api import request
from volatility3.framework import exceptions, renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class CryptoScan(interfaces.plugins.PluginInterface):
    """Prints the memory map"""

    _required_framework_version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (2, 0, 0)),
            requirements.IntRequirement(name = 'pid',
                                        description = "Process ID to include (all other processes are excluded)",
                                        optional = True),
            requirements.BooleanRequirement(name = 'btc',
                                            description = "print bitcoin address",
                                            default = False,
                                            optional = True),
            requirements.BooleanRequirement(name = 'xrp',
                                            description = "print xrp address",
                                            default = False,
                                            optional = True),
            requirements.BooleanRequirement(name = 'eth',
                                            description = "print eth address",
                                            default = False,
                                            optional = True)
        ]

    def _generator(self, procs):
        

        for proc in procs:
            pid = "Unknown"

            try:
                pid = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()
                proc_layer = self.context.layers[proc_layer_name]
            except exceptions.InvalidAddressException as excp:
                vollog.debug("Process {}: invalid address {} in layer {}".format(pid, excp.invalid_address,
                                                                                 excp.layer_name))
                continue

            file_handle = self.open("pid.{}.dmp".format(pid))
            with file_handle as file_data:
                
                json_Reg = re.compile(r'\{.*\:\{.*\:.*\}\}') #json
                ripple_reg = re.compile(r'r[0-9a-zA-Z]{33,35}')
                btc_reg = re.compile(r'\b(bc(0([ac-hj-np-z02-9]{39}|[ac-hj-np-z02-9]{59})|1[ac-hj-np-z02-9]{8,87})|[13][a-km-zA-HJ-NP-Z1-9]{25,35})\b')
                eth_reg = re.compile(r'0x[a-fA-F0-9]{40}')
                transactions_reg = re.compile(r'[A-Fa-f0-9]{64}')

                duplicated_str = []
                printed_str = []
                backup_offset = 0
                backup_mapped_offset = 0
                backup_mapped_size = 0


                t_backup_offset = 0
                t_backup_mapped_offset = 0
                t_backup_mapped_size = 0

                for mapval in proc_layer.mapping(0x0, proc_layer.maximum_address, ignore_errors = True):
                    offset, size, mapped_offset, mapped_size, maplayer = mapval
                    #print(mapval)
                    ripple_recv_list = []
                    btc_recv_list = []
                    eth_recv_list = []
                    transaction_list = []
                    rippple_transaction_list = []

                    file_output = "Disabled"
                    
                    try:
                        data = proc_layer.read(offset, size, pad = True)
                        #file_data.write(data)
                        buf = ''
                        for b in data:
                            buf += chr(b)
                        
                        if json_Reg.search(buf):
                            if self.config['xrp']:
                                for j in ripple_reg.findall(buf): 
                                    if j not in ripple_recv_list:
                                        if j not in duplicated_str:
                                            ripple_recv_list.append(j)
                                            duplicated_str.append(j)

                            if self.config['btc']:
                                if 'address' in buf:
                                    for j in btc_reg.findall(buf):
                                        if j not in btc_recv_list:
                                            if j not in duplicated_str:
                                                btc_recv_list.append(j)
                                                duplicated_str.append(j)

                            if self.config['eth']:
                                if 'address' in buf:
                                    for j in eth_reg.findall(buf):
                                        if j not in eth_recv_list:
                                            #print(j)
                                            if j not in duplicated_str:
                                                eth_recv_list.append(j)
                                                duplicated_str.append(j)

                            if self.config['xrp']:
                                if transactions_reg.search(buf):
                                    if 'hash' in buf and 'ripple' in buf:
                                        for j in transactions_reg.findall(buf):
                                            if j not in rippple_transaction_list:
                                                if j not in duplicated_str:
                                                    rippple_transaction_list.append(j)
                                                    duplicated_str.append(j)

                            if transactions_reg.search(buf):
                                for j in transactions_reg.findall(buf):
                                    if j not in transaction_list:
                                        if j not in duplicated_str:
                                            transaction_list.append(j)
                                            duplicated_str.append(j)

                        file_output = file_handle.preferred_filename
                    except exceptions.InvalidAddressException:
                        file_output = "Error outputting to file"
                        vollog.debug("Unable to write {}'s address {} to {}".format(
                            proc_layer_name, offset, file_handle.preferred_filename))
                            
                    if self.config['xrp']:
                        for adres in ripple_recv_list:
                                
                            APIKEY = '78b77cc0d045f94d99889a64872a4d021172cbf5'
                            BASE = 'https://rest.cryptoapis.io/v2'
                            address = adres
                            NETWORK = 'testnet'
    
                            with requests.Session() as session:
                                h = {
                                              'Content-Type': "application/json",
                                              'X-API-Key': "78b77cc0d045f94d99889a64872a4d021172cbf5"
                                            }
    
                                r = session.get(
                                    f'{BASE}/blockchain-data/xrp-specific/{NETWORK}/addresses/{address}/transactions?limit=50&offset=10&transactionType=payment', headers=h)
                                
                                result = json.loads(json.dumps(r.json()))
                                #print(result)
                                if not result.get('error'):
                                    if adres not in printed_str:
                                        printed_str.append(adres)
                                        #print(backup_offset)

                                        if backup_offset == offset and backup_mapped_offset != mapped_offset and backup_mapped_size != mapped_size:
                                            yield (0, ('='*len((str(hex(offset)))), str(hex(mapped_offset)), str(hex(mapped_size)),
                                               '='*64, adres))

                                        elif backup_offset == offset and backup_mapped_offset != mapped_offset and backup_mapped_size == mapped_size: 
                                            yield (0, ('='*len((str(hex(offset)))), str(hex(mapped_offset)), '='*len((str(hex(mapped_size)))),
                                               '='*64, adres))
                                        
                                        elif backup_offset == offset and backup_mapped_offset == mapped_offset and backup_mapped_size != mapped_size: 
                                            yield (0, ('='*len((str(hex(offset)))), '='*len((str(hex(mapped_offset)))), str(hex(mapped_size)),
                                               '='*64, adres))
                                        
                                        elif backup_offset != offset and backup_mapped_offset == mapped_offset and backup_mapped_size == mapped_size:
                                            yield (0, (str(hex(offset)), '='*len((str(hex(mapped_offset)))), '='*len((str(hex(mapped_size)))),
                                               '='*64, adres))

                                        elif backup_offset != offset and backup_mapped_offset != mapped_offset and backup_mapped_size != mapped_size:
                                            yield (0, (str(hex(offset)), str(hex(mapped_offset)), str(hex(mapped_size)),
                                               '='*64, adres))
                                        else:
                                            yield (0, ('='*len((str(hex(offset)))), '='*len((str(hex(mapped_offset)))), '='*len((str(hex(mapped_size)))),
                                               '='*64, adres))

                                    backup_offset = offset
                                    backup_mapped_offset = mapped_offset
                                    backup_mapped_size = mapped_size

                    if self.config['btc']:    
                        for adres in btc_recv_list:
                            tmp = str(adres).replace('(','').replace(')','').replace("'",'').replace(',','')
                            address_list = tmp.split(' ')

                            for ad in address_list:
                                response = requests.get('https://www.blockchain.com/btc/address/'+ad)
                                #print(response.url)
                                #print(response.status_code)

                                if ad != '':
                                    if response.status_code == 200:
                                        if backup_offset == offset and backup_mapped_offset != mapped_offset and backup_mapped_size != mapped_size:
                                            yield (0, ('='*len((str(hex(offset)))), str(hex(mapped_offset)), str(hex(mapped_size)),
                                               '='*64, ad))

                                        elif backup_offset == offset and backup_mapped_offset != mapped_offset and backup_mapped_size == mapped_size: 
                                            yield (0, ('='*len((str(hex(offset)))), str(hex(mapped_offset)), '='*len((str(hex(mapped_size)))),
                                               '='*64, ad))
                                        
                                        elif backup_offset == offset and backup_mapped_offset == mapped_offset and backup_mapped_size != mapped_size: 
                                            yield (0, ('='*len((str(hex(offset)))), '='*len((str(hex(mapped_offset)))), str(hex(mapped_size)),
                                               '='*64, ad))
                                        
                                        elif backup_offset != offset and backup_mapped_offset == mapped_offset and backup_mapped_size == mapped_size:
                                            yield (0, (str(hex(offset)), '='*len((str(hex(mapped_offset)))), '='*len((str(hex(mapped_size)))),
                                               '='*64, ad))

                                        elif backup_offset != offset and backup_mapped_offset != mapped_offset and backup_mapped_size != mapped_size:
                                            yield (0, (str(hex(offset)), str(hex(mapped_offset)), str(hex(mapped_size)),
                                               '='*64, ad))
                                        else:
                                            yield (0, ('='*len((str(hex(offset)))), '='*len((str(hex(mapped_offset)))), '='*len((str(hex(mapped_size)))),
                                               '='*64, ad))


                                #print(check)
                                backup_offset = offset
                                backup_mapped_offset = mapped_offset
                                backup_mapped_size = mapped_size

                    if self.config['eth']:    
                        for adres in eth_recv_list:
                            response = requests.get('https://www.blockchain.com/eth/address/'+adres)
                            #print(response.url)
                            if adres != '':
                                if adres != '0x0000000000000000000000000000000000000000':
                                    if response.status_code == 200:

                                        if backup_offset == offset and backup_mapped_offset != mapped_offset and backup_mapped_size != mapped_size:
                                            yield (0, ('='*len((str(hex(offset)))), str(hex(mapped_offset)), str(hex(mapped_size)),
                                               '='*64, adres))

                                        elif backup_offset == offset and backup_mapped_offset != mapped_offset and backup_mapped_size == mapped_size: 
                                            yield (0, ('='*len((str(hex(offset)))), str(hex(mapped_offset)), '='*len((str(hex(mapped_size)))),
                                               '='*64, adres))
                                        
                                        elif backup_offset == offset and backup_mapped_offset == mapped_offset and backup_mapped_size != mapped_size: 
                                            yield (0, ('='*len((str(hex(offset)))), '='*len((str(hex(mapped_offset)))), str(hex(mapped_size)),
                                               '='*64, adres))
                                        
                                        elif backup_offset != offset and backup_mapped_offset == mapped_offset and backup_mapped_size == mapped_size:
                                            yield (0, (str(hex(offset)), '='*len((str(hex(mapped_offset)))), '='*len((str(hex(mapped_size)))),
                                               '='*64, adres))

                                        elif backup_offset != offset and backup_mapped_offset != mapped_offset and backup_mapped_size != mapped_size:
                                            yield (0, (str(hex(offset)), str(hex(mapped_offset)), str(hex(mapped_size)),
                                               '='*64, adres))
                                        else:
                                            yield (0, ('='*len((str(hex(offset)))), '='*len((str(hex(mapped_offset)))), '='*len((str(hex(mapped_size)))),
                                               '='*64, adres))

                            backup_offset = offset
                            backup_mapped_offset = mapped_offset
                            backup_mapped_size = mapped_size

                    if self.config['btc'] or self.config['eth']:
                        for transaction in transaction_list:
                            if not '00000000000000' in transaction:
                                #if transaction[0] != transaction[1]:
                                  #  yield (0, (str(hex(offset)), str(hex(mapped_offset)), str(hex(mapped_size)),
                                    #                          transaction, '='*50))
                                url = 'https://www.blockchain.com'

                                if self.config['btc']:
                                    url = url + '/btc/tx/'

                                elif self.config['xrp']:
                                    test = 1

                                elif self.config['eth']:
                                    url = url + '/eth/tx/'

                                try:
                                    response =requests.get(url+transaction)
                                    #print(response.url)
                                    if response.status_code == 200:
                                        
                                        if t_backup_offset == offset and t_backup_mapped_offset != mapped_offset and t_backup_mapped_size != mapped_size:
                                            yield (0, ('='*len((str(hex(offset)))), str(hex(mapped_offset)), str(hex(mapped_size)),
                                               transaction, '='*42))

                                        elif t_backup_offset == offset and t_backup_mapped_offset != mapped_offset and t_backup_mapped_size == mapped_size: 
                                            yield (0, ('='*len((str(hex(offset)))), str(hex(mapped_offset)), '='*len((str(hex(mapped_size)))),
                                               transaction, '='*42))
                                        
                                        elif t_backup_offset == offset and t_backup_mapped_offset == mapped_offset and t_backup_mapped_size != mapped_size: 
                                            yield (0, ('='*len((str(hex(offset)))), '='*len((str(hex(mapped_offset)))), str(hex(mapped_size)),
                                               transaction, '='*42))
                                        
                                        elif t_backup_offset != offset and t_backup_mapped_offset == mapped_offset and t_backup_mapped_size == mapped_size:
                                            yield (0, (str(hex(offset)), '='*len((str(hex(mapped_offset)))), '='*len((str(hex(mapped_size)))),
                                               transaction, '='*42))

                                        elif t_backup_offset != offset and t_backup_mapped_offset != mapped_offset and t_backup_mapped_size != mapped_size:
                                            yield (0, (str(hex(offset)), str(hex(mapped_offset)), str(hex(mapped_size)),
                                               transaction, '='*42))
                                        else:
                                            yield (0, ('='*len((str(hex(offset)))), '='*len((str(hex(mapped_offset)))), '='*len((str(hex(mapped_size)))),
                                               transaction, '='*42))

                                        t_backup_offset = offset
                                        t_backup_mapped_offset = mapped_offset
                                        t_backup_mapped_size = mapped_size
                                               
                                except:
                                    yield (0, (str(hex(offset)), str(hex(mapped_offset)), str(hex(mapped_size)),
                                                              'not confirmed: '+ transaction, '='*42)) 


                    else:
                        for transaction in rippple_transaction_list:
                            if not '00000000000000' in transaction:
                                if t_backup_offset == offset and t_backup_mapped_offset != mapped_offset and t_backup_mapped_size != mapped_size:
                                            yield (0, ('='*len((str(hex(offset)))), str(hex(mapped_offset)), str(hex(mapped_size)),
                                               transaction, '='*42))

                                elif t_backup_offset == offset and t_backup_mapped_offset != mapped_offset and t_backup_mapped_size == mapped_size: 
                                            yield (0, ('='*len((str(hex(offset)))), str(hex(mapped_offset)), '='*len((str(hex(mapped_size)))),
                                               transaction, '='*42))

                                elif t_backup_offset == offset and t_backup_mapped_offset == mapped_offset and t_backup_mapped_size != mapped_size: 
                                            yield (0, ('='*len((str(hex(offset)))), '='*len((str(hex(mapped_offset)))), str(hex(mapped_size)),
                                               transaction, '='*42))
                                
                                elif t_backup_offset != offset and t_backup_mapped_offset == mapped_offset and t_backup_mapped_size == mapped_size:
                                            yield (0, (str(hex(offset)), '='*len((str(hex(mapped_offset)))), '='*len((str(hex(mapped_size)))),
                                               transaction, '='*42))

                                elif t_backup_offset != offset and t_backup_mapped_offset != mapped_offset and t_backup_mapped_size != mapped_size:
                                    yield (0, (str(hex(offset)), str(hex(mapped_offset)), str(hex(mapped_size)),
                                       transaction, '='*42))
                                else:
                                    yield (0, ('='*len((str(hex(offset)))), '='*len((str(hex(mapped_offset)))), '='*len((str(hex(mapped_size)))),
                                       transaction, '='*42))

                                t_backup_offset = offset
                                t_backup_mapped_offset = mapped_offset
                                t_backup_mapped_size = mapped_size
    
                    offset += mapped_size
                    #print('offset: 0x%x'%offset)

    def run(self):
        filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])

        return renderers.TreeGrid([("      Virtual", str), ("  Physical", str),
                                   ("  Size", str), (' '*60 + "TXID", str), ("address", str)],
                                  self._generator(
                                      pslist.PsList.list_processes(context = self.context,
                                                                   layer_name = self.config['primary'],
                                                                   symbol_table = self.config['nt_symbols'],
                                                                   filter_func = filter_func)))