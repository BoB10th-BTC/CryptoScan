import logging, re
from typing import List
import requests
import json
import time
import datetime

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

                address_count = 0
                tx_count = 0

                duplicated_str = []
                printed_str = []
                check_pdf_list = []

                transaction_list = []
                rippple_transaction_list = []

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
                            balance = '0'
                            
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
                                        check_pdf_list.append(adres)
                                        with requests.Session() as sess:
                                            hd = {
                                                          'Content-Type': "application/json",
                                                          'X-API-Key': "78b77cc0d045f94d99889a64872a4d021172cbf5"
                                                        }

                                            req = sess.get(
                                                f'{BASE}/blockchain-data/xrp-specific/{NETWORK}/addresses/{address}?context=', headers=hd)
                                            result_balance = json.loads(json.dumps(req.json()))
                                            
                                            address_count += 1

                                            if 'amount' not in str(result_balance):
                                                #print('1')
                                                #print(result_balance.get('data').get('item'))
                                                balance = '0'
                                            
                                            else:
                                                #print(result_balance.get('data').get('item'))
                                                balance = str(result_balance.get('data').get('item').get('balance').get('amount'))

                                            check_pdf_list.append(balance)

                                            if backup_offset == offset and backup_mapped_offset != mapped_offset and backup_mapped_size != mapped_size:
                                                yield (0, ('='*len((str(hex(offset)))), str(hex(mapped_offset)), str(hex(mapped_size)),
                                                   adres,balance))

                                            elif backup_offset == offset and backup_mapped_offset != mapped_offset and backup_mapped_size == mapped_size: 
                                                yield (0, ('='*len((str(hex(offset)))), str(hex(mapped_offset)), '='*len((str(hex(mapped_size)))),
                                                   adres,balance))

                                            elif backup_offset == offset and backup_mapped_offset == mapped_offset and backup_mapped_size != mapped_size: 
                                                yield (0, ('='*len((str(hex(offset)))), '='*len((str(hex(mapped_offset)))), str(hex(mapped_size)),
                                                   adres,balance))

                                            elif backup_offset != offset and backup_mapped_offset == mapped_offset and backup_mapped_size == mapped_size:
                                                yield (0, (str(hex(offset)), '='*len((str(hex(mapped_offset)))), '='*len((str(hex(mapped_size)))),
                                                   adres,balance))

                                            elif backup_offset != offset and backup_mapped_offset != mapped_offset and backup_mapped_size != mapped_size:
                                                yield (0, (str(hex(offset)), str(hex(mapped_offset)), str(hex(mapped_size)),
                                                   adres,balance))
                                            else:
                                                yield (0, ('='*len((str(hex(offset)))), '='*len((str(hex(mapped_offset)))), '='*len((str(hex(mapped_size)))),
                                                   adres,balance))

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
                                        res = requests.get('https://chain.api.btc.com/v3/address/'+ad)
                                        result = json.loads(json.dumps(res.json()))

                                        if result.get('status') == 'success':
                                            #print(result.get('data').get('received'))
                                            if backup_offset == offset and backup_mapped_offset != mapped_offset and backup_mapped_size != mapped_size:
                                                yield (0, ('='*len((str(hex(offset)))), str(hex(mapped_offset)), str(hex(mapped_size)),
                                                   ad,result.get('data').get('balance')))

    
                                            elif backup_offset == offset and backup_mapped_offset != mapped_offset and backup_mapped_size == mapped_size: 
                                                yield (0, ('='*len((str(hex(offset)))), str(hex(mapped_offset)), '='*len((str(hex(mapped_size)))),
                                                   ad,str(result.get('data').get('balance'))))
                                            
                                            elif backup_offset == offset and backup_mapped_offset == mapped_offset and backup_mapped_size != mapped_size: 
                                                yield (0, ('='*len((str(hex(offset)))), '='*len((str(hex(mapped_offset)))), str(hex(mapped_size)),
                                                   ad,str(result.get('data').get('balance'))))
                                            
                                            elif backup_offset != offset and backup_mapped_offset == mapped_offset and backup_mapped_size == mapped_size:
                                                yield (0, (str(hex(offset)), '='*len((str(hex(mapped_offset)))), '='*len((str(hex(mapped_size)))),
                                                   ad,str(result.get('data').get('balance'))))
    
                                            elif backup_offset != offset and backup_mapped_offset != mapped_offset and backup_mapped_size != mapped_size:
                                                yield (0, (str(hex(offset)), str(hex(mapped_offset)), str(hex(mapped_size)),
                                                   ad,str(result.get('data').get('balance'))))
                                            else:
                                                yield (0, ('='*len((str(hex(offset)))), '='*len((str(hex(mapped_offset)))), '='*len((str(hex(mapped_size)))),
                                                   ad,str(result.get('data').get('balance'))))
    

                                #print(check)
                                backup_offset = offset
                                backup_mapped_offset = mapped_offset
                                backup_mapped_size = mapped_size

                    if self.config['eth']:    
                        for adres in eth_recv_list:
                            response = requests.get('https://www.blockchain.com/eth/address/'+adres)
                            #print(response.url)
                            API_KEY = 'W7M246525TUVWK8MACMD58I9RD9FFURUUK'
                            url = 'https://api.etherscan.io/api?module=account&action=balance&address='+adres+'&tag=latest&apikey='+API_KEY
                            if adres != '':
                                if adres != '0x0000000000000000000000000000000000000000':
                                    if response.status_code == 200:
                                        res = requests.get(url)
                                        result = json.loads(json.dumps(res.json()))

                                        if backup_offset == offset and backup_mapped_offset != mapped_offset and backup_mapped_size != mapped_size:
                                            yield (0, ('='*len((str(hex(offset)))), str(hex(mapped_offset)), str(hex(mapped_size)),
                                               adres,str(result.get('result'))))

                                        elif backup_offset == offset and backup_mapped_offset != mapped_offset and backup_mapped_size == mapped_size: 
                                            yield (0, ('='*len((str(hex(offset)))), str(hex(mapped_offset)), '='*len((str(hex(mapped_size)))),
                                               adres,str(result.get('result'))))
                                        
                                        elif backup_offset == offset and backup_mapped_offset == mapped_offset and backup_mapped_size != mapped_size: 
                                            yield (0, ('='*len((str(hex(offset)))), '='*len((str(hex(mapped_offset)))), str(hex(mapped_size)),
                                               adres,str(result.get('result'))))
                                        
                                        elif backup_offset != offset and backup_mapped_offset == mapped_offset and backup_mapped_size == mapped_size:
                                            yield (0, (str(hex(offset)), '='*len((str(hex(mapped_offset)))), '='*len((str(hex(mapped_size)))),
                                               adres,str(result.get('result'))))

                                        elif backup_offset != offset and backup_mapped_offset != mapped_offset and backup_mapped_size != mapped_size:
                                            yield (0, (str(hex(offset)), str(hex(mapped_offset)), str(hex(mapped_size)),
                                               adres,str(result.get('result'))))
                                        else:
                                            yield (0, ('='*len((str(hex(offset)))), '='*len((str(hex(mapped_offset)))), '='*len((str(hex(mapped_size)))),
                                               adres,str(result.get('result'))))

                            backup_offset = offset
                            backup_mapped_offset = mapped_offset
                            backup_mapped_size = mapped_size
    
                    offset += mapped_size
                    #print('offset: 0x%x'%offset)
            if self.config['btc']:
                yield (0, ('', '', '', '', ''))
                yield (0, (' '*60+'TXID',' '*8 + 'Time',' '*8+ 'Sender', ' '*40 + 'Recipient', ' '*36+'Amount'))

                for transaction in transaction_list:
                            if not '00000000000000' in transaction:
                                #if transaction[0] != transaction[1]:
                                  #  yield (0, (str(hex(offset)), str(hex(mapped_offset)), str(hex(mapped_size)),
                                    #                          transaction, '='*50))
                                url = 'https://www.blockchain.com'

                                if self.config['btc']:
                                    url = url + '/btc/tx/'

                                response =requests.get(url+transaction)
                                #print(response.url)
                                if response.status_code == 200:
                                    try:
                                        res = requests.get('https://chain.api.btc.com/v3/tx/'+transaction)
                                        result = json.loads(json.dumps(res.json()))
                                        creation_time = str(result.get('data').get('created_at'))
                                        str_time = time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(int(creation_time)-time.timezone))
                                        sender = result.get('data').get('inputs')[0].get('prev_addresses')[0]
                                        recipient = result.get('data').get('outputs')[1].get('addresses')[0]
                                        amount = str(result.get('data').get('inputs_value'))
                                        yield (0, (transaction,str_time,sender,recipient,amount))
                                    except:
                                        res = requests.get('https://chain.api.btc.com/v3/tx/'+transaction)
                                        result = json.loads(json.dumps(res.json()))
                                        creation_time = str(result.get('data').get('created_at'))
                                        str_time = time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(int(creation_time)-time.timezone))
                                        sender = result.get('data').get('inputs')[0].get('prev_addresses')[0]
                                        recipient = result.get('data').get('outputs')[0].get('addresses')[0]
                                        amount = str(result.get('data').get('inputs_value'))
                                        yield (0, (transaction,str_time,sender,recipient,amount))
            
            if self.config['eth']:
                yield (0, ('', '', '', '', ''))
                yield (0, (' '*60+'TXID',' '*8 + 'Time',' '*8+ 'Sender', ' '*40 + 'Recipient', ' '*36+'Amount'))

                for transaction in transaction_list:
                            if not '00000000000000' in transaction:
                                #if transaction[0] != transaction[1]:
                                  #  yield (0, (str(hex(offset)), str(hex(mapped_offset)), str(hex(mapped_size)),
                                    #                          transaction, '='*50))
                                url = 'https://www.blockchain.com'

                                if self.config['eth']:
                                    url = url + '/eth/tx/'

                                response =requests.get(url+transaction)
                                #print(response.url)
                                if response.status_code == 200:
                                    res = requests.get('https://api.blockchair.com/ethereum/dashboards/transaction/'+'0x'+transaction)
                                    result = json.loads(json.dumps(res.json()))
                                    creation_time = result.get('data').get('0x'+transaction).get('transaction').get('time')
                                    
                                    sender = result.get('data').get('0x'+transaction).get('transaction').get('sender')
                                    recipient = result.get('data').get('0x'+transaction).get('transaction').get('recipient')
                                    amount = str(result.get('data').get('0x'+transaction).get('calls')[0].get('value'))
                                    yield (0, (transaction,creation_time,sender,recipient,amount))

            if self.config['xrp']:
                yield (0, ('', '', '', '', ''))
                yield (0, (' '*60+'TXID',' '*8 + 'Time',' '*17+ 'Sender', ' '*33 + 'Recipient', ' '*26+'Amount'))
                
                for transaction in rippple_transaction_list:
                            if not '00000000000000' in transaction:
                                try:
                                    headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36'}
                                    res = requests.get('https://api.xrpscan.com/api/v1/tx/'+transaction, headers=headers)
                                    result = json.loads(json.dumps(res.json()))
                                    creation_time = result.get('date')
                                    sender = result.get('Account')
                                    recipient = result.get('Destination')
                                    amount = str(result.get('Amount').get('value'))
                                    yield (0, (transaction,creation_time,sender,recipient,amount))
                                    check_pdf_list.append(transaction)
                                    check_pdf_list.append(creation_time)
                                    check_pdf_list.append(sender)
                                    check_pdf_list.append(recipient)
                                    check_pdf_list.append(amount)

                                    tx_count += 1
                                except:
                                    not_checked = 1
            
            check_pdf_list.insert(0,str(address_count))
            print(check_pdf_list)
    
    def run(self):
        filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])

        return renderers.TreeGrid([("      Virtual", str), ("  Physical", str),
                                   ("  Size", str), ("Address", str),(' '*40+"Balance", str)],
                                  self._generator(
                                      pslist.PsList.list_processes(context = self.context,
                                                                   layer_name = self.config['primary'],
                                                                   symbol_table = self.config['nt_symbols'],
                                                                   filter_func = filter_func)))