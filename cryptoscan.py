import logging, re
from typing import List
import requests
import json
import time
import datetime
import enchant
import os

import time, pytz, requests
from datetime import datetime
from itertools import zip_longest
import reportlab.pdfbase.pdfform as pdfform
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Flowable
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet

from fake_useragent import UserAgent
from requests.api import request
from volatility3.framework import exceptions, renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)
styles = getSampleStyleSheet()
style = styles["Normal"]
styleBody = styles["BodyText"]
styleBody.wordWrap = 'CJK'
styleBody.alignment = TA_CENTER

class SignatureDate(Flowable):
    def __init__(self, x=30, y=10, width=60, height=120, name=1):
        Flowable.__init__(self)
        self.x = x
        self.y = y
        self.width = width
        self.height = height
        self.name = name

    def draw(self):
        c = self.canv
        ### Signature ###
        c.drawString(self.x, self.y, f"{self.name} Signature")
        c.rect(self.x, self.y - 5 - self.height, self.width, self.height)
        pdfform.textFieldRelative(c, "textfield_Sign" + str(self.name), self.x, self.y - 5 - self.height, self.width, self.height, "")

        ### Date ###
        c.drawString(self.x + self.width + 5, self.y, "Date (DD-MMM-YYYY)")
        c.rect(self.x + self.width + 5, self.y - 5 - self.height,(self.width / 2.0) + 70, self.height)
        pdfform.textFieldRelative(c, "textfield_Date" + str(self.name), self.x + self.width + 5, self.y - 5 - self.height, (self.width / 2.0) + 70, self.height, "")

        ### Print Name ###
        c.drawString(self.x + (self.width * 1.5 + 80), self.y, "Print Name")
        c.rect(self.x + (self.width * 1.5) + 80, self.y - 5 - self.height, self.width, self.height)
        pdfform.textFieldRelative(c, "textfield_Print" + str(self.name), self.x + (self.width * 1.5) + 80, self.y - 5 - self.height, self.width, self.height, "")

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        canvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def drawHeader(self):
        width = 2 * inch
        height = 0.5 * inch
        img_x = self.pagesize[0] - width - 0.05 * inch
        img_y = self.pagesize[1] - (0.75 * inch)
        self.drawImage(r"D:/tools/volatility3-1.0.1/volatility3-1.0.1/volatility3/framework/plugins/windows/bob.jpg",x=img_x, y=img_y, width=width, height=height, preserveAspectRatio=True)

    def save(self): # page x of y
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.drawPageNumber(num_pages)
            self.drawHeader()
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def drawPageNumber(self, page_count):
        self.setFont('Helvetica', 11)
        self.drawRightString((15 * self.pagesize[0] / 16.0), 0.1 * inch + (0.4 * inch), "Page %d of %d" % (self._pageNumber, page_count))
        self.drawString((self.pagesize[0] / 20.0), 0.1 * inch + (0.4 * inch), "Made by BoB 10th Team BTC (BoB Tracers' of Coin)")

class BaseReport(object):
    def __init__(self, doc_title, make_landscape=False):
        self.elements = []
        style.spaceBefore = 5
        self.doc_title = doc_title
        self.landscape = False
        if make_landscape:
            self.pagesize = A4
            self.landscape = True
        else:
            self.pagesize = A4

    def header(self, canvas, doc):
        textobject = canvas.beginText()
        textobject.setFont(style.fontName, 16)
        textobject.setTextOrigin((self.pagesize[0] / 16.0), self.pagesize[1] - (0.55 * inch))
        textobject.textLine(text=self.doc_title)
        canvas.drawText(textobject)

    def buildDocument(self, filepath=None):
        doc = SimpleDocTemplate(filepath,
                                title=self.doc_title,
                                pagesize=self.pagesize,
                                leftMargin=inch * 0.5,
                                rightMargin=inch * 0.5,
                                topMargin=inch * 0.8,
                                bottomMargin=inch * 0.8)
        NumberedCanvas.pagesize = self.pagesize
        elements = self.elements.copy()
        doc.build(
            elements,
            onFirstPage=self.header,
            onLaterPages=self.header,
            canvasmaker=NumberedCanvas)

    def createAddrTable(self, tableData, widths=None, colOrder=None):

        
        if isinstance(tableData[0], dict):
            tmp = []
            if colOrder is None:
                colOrder = [value for value in tableData[0].keys()]
            tmp.append(
                [Paragraph(str(value).replace(' ', '<br />'), styleBody) for value in colOrder])
            for tableDict in tableData:
                tmp.append([Paragraph(str(tableDict[key]), styleBody) for key in colOrder])
            tableData = tmp

        addrTable = Table(tableData, repeatRows=(0, ), colWidths=widths)

        addrTableStyle = TableStyle(
                [('ALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                 ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                 ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.lightgrey),
                 ('LINEBELOW', (0, 0), (-1, 0), 1, colors.black),
                 ('OUTLINE', (0, 0), (-1, -1), 1, colors.lightgrey),
                 ('LEFTPADDING', (0, 0), (-1, -1), 1),
                 ('RIGHTPADDING', (0, 0), (-1, -1), 1),
                 ('TOPPADDING', (0, 0), (-1, -1), 1),
                 ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
                 ])
        addrTable.setStyle(addrTableStyle)
        self.elements.append(Paragraph(str("Cryptocurrency Transaction Info - Wallet Address"), styles['Heading2']))
        self.elements.append(addrTable)

    def createTxTable(self, tableData, widths=None, colOrder=None):

        if isinstance(tableData[0], dict):
            tmp = []
            if colOrder is None:
                colOrder = [value for value in tableData[0].keys()]
            tmp.append(
                [Paragraph(str(value).replace(' ', '<br />'), styleBody) for value in colOrder])
            for tableDict in tableData:
                tmp.append([Paragraph(str(tableDict[key]), styleBody) for key in colOrder])
            tableData = tmp

        txTable = Table(tableData, repeatRows=(0, ), colWidths=widths)

        txTableStyle = TableStyle(
                [('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                 ('ALIGN', (1, 1), (-1, -1), 'LEFT'),
                 ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.lightgrey),
                 ('INNERGRID', (1, 5), (0, 0), 0.25, colors.black),
                 ('LINEBELOW', (0, 0), (-1, 0), 1, colors.black),
                 ('OUTLINE', (0, 0), (-1, -1), 1, colors.lightgrey),
                 ('LEFTPADDING', (0, 0), (-1, -1), 1),
                 ('RIGHTPADDING', (0, 0), (-1, -1), 1),
                 ('TOPPADDING', (0, 0), (-1, -1), 1),
                 ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
                 ])

        txTable.setStyle(txTableStyle)
        self.elements.append(Paragraph(str("Cryptocurrency Transaction Info - Transaction Info"), styles['Heading2']))
        self.elements.append(txTable)


    def createTxLink(self, tableData, widths=None, colOrder=None):

        if isinstance(tableData[0], dict):
            tmp = []
            if colOrder is None:
                colOrder = [value for value in tableData[0].keys()]
            tmp.append(
                [Paragraph(str(value).replace(' ', '<br />'), styleBody) for value in colOrder])
            for tableDict in tableData:
                tmp.append([Paragraph(str(tableDict[key]), styleBody) for key in colOrder])
            tableData = tmp

        txLink = Table(tableData, repeatRows=(0, ), colWidths=widths)

        txLinkStyle = TableStyle(
                [('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                 ('ALIGN', (1, 1), (-1, -1), 'LEFT'),
                 ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.lightgrey),
                 ('LINEBELOW', (0, 0), (-1, 0), 1, colors.black),
                 ('OUTLINE', (0, 0), (-1, -1), 1, colors.lightgrey),
                 ('LEFTPADDING', (0, 0), (-1, -1), 1),
                 ('RIGHTPADDING', (0, 0), (-1, -1), 1),
                 ('TOPPADDING', (0, 0), (-1, -1), 1),
                 ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
                 ])

        txLink.setStyle(txLinkStyle)
        self.elements.append(Paragraph(str("More at Other Platforms"), styles['Heading2']))
        self.elements.append(txLink)


    def grouper(self, iterable, group_size, fillvalue=None):
        args = [iter(iterable)] * group_size
        return list(zip_longest(fillvalue=fillvalue, *args))

    def createSummary(self, summary):
        table_data = [Paragraph(f"<b>{summary}:</b> {info}", style) for summary, info in summary.items()]
        columns = 1
        if self.landscape:  
            columns = 1
        tableData = self.grouper(table_data, columns)

        addrTable = Table(tableData)
        addrTable.setStyle(TableStyle([('VALIGN', (0, 0), (-1, -1), 'MIDDLE')]))
        self.elements.append(addrTable)

    def createReport(self, data, widths,addrTableData,txTableData,txLinkData):
        if(data==addrTableData):
            self.createAddrTable(data, widths)
        elif(data==txTableData):
            self.createTxTable(data, widths)
        elif(data==txLinkData):
            self.createTxLink(data, widths)    
        self.elements.append(Spacer(0, inch * 0.05))

def getAddr(inputData,inputAddrCount):
    res = []    
    for k in range(2, (inputAddrCount)*3+2, 3):    
        res += inputData[k], inputData[k+1], inputData[k+2]
    return res

def getTx(inputData,inputAddrCount):
    res = []
    for k in range((inputAddrCount)*3+2, len(inputData), 5):
        res += inputData[k], inputData[k+1], inputData[k+2], inputData[k+3], inputData[k+4]
    return res

def setDoc(inputAddrCount, inputTxCount, addrTableData, txTableData, txLinkData,inputData):
    
    doc_title = "CryptoScan Report"
    test = BaseReport(doc_title, make_landscape=True)

    
    summary = {
        'Report Name': 'CryptoScan_' + time.strftime('%m%d'),
        'Report Created': datetime.now().astimezone(pytz.timezone('Asia/Seoul')),
        'Analysis Version': '1.0',
        'Target File Name (size)': 'xxxxxxx.mem (4GB)',
        'Target File Path: ': 'C:\XXXX'
    }
    
    for i in range(inputTxCount):
        txTableData+=([['TXID'], ['Time'], ['Sender'], ['Receiver'], ['Amount']])
    
    for i in range(0, inputAddrCount * 3, 3): # 12
        val1 = [getAddr(inputData,inputAddrCount)[i], getAddr(inputData,inputAddrCount)[i+1], getAddr(inputData,inputAddrCount)[i+2]]
        addrTableData.append(val1)
                
    for j in range(0, inputTxCount*5): # 20
        txTableData[j+1].append(getTx(inputData,inputAddrCount)[j])


            
    # btc.com
    url = []
    for k in range(int(inputData[0]) * 3 + 2, len(inputData), 5): # 14, 19, 24, 29
        if(reqtype != 'ripple'):
            tmp = 'https://btc.com/btc/search?q='
        else:
            tmp = 'https://xrpscan.com/tx/'
        url.append(bitlyUrl(tmp+inputData[k]))

    for k, l in enumerate(url, start=1):
        val2 = [k, l]
        txLinkData.append(val2)

    test.createSummary(summary) #addrTableData,txTableData,txLinkData
    test.createReport(addrTableData, ['50%', '43%', '7%'],addrTableData,txTableData,txLinkData)
    test.createReport(txTableData, ['20%', '80%'],addrTableData,txTableData,txLinkData)
    test.createReport(txLinkData, ['10%', '90%'],addrTableData,txTableData,txLinkData)

    test.buildDocument(r'Cryptoscan_Report.pdf')

def setNumFormat(inputData):
    
    for i in range(1, int(inputData[1]) + 1):
        idx = 1 + int(inputData[0]) * 3 + 5 * i
        inputData[idx] = format(int(inputData[idx]), ',')
  
    for j in range(3, int(inputData[0])*3 + 1, 3): # 3 6 9 12
        global reqtype
        if(inputData[j+1] == 'XRP'):
            reqtype = "ripple"
        elif(inputData[j+1] == 'BTC'):
            reqtype = "bitcoin"
        elif(inputData[j+1] == 'ETH'):
            reqtype = 'ethereum'
        else:
            print("Input Data Error")
        response = requests.get("https://api.coingecko.com/api/v3/simple/price?ids="+reqtype+"&vs_currencies=usd")
        marketPrice = response.json()[reqtype]['usd'] * float(inputData[j])
        inputData[j] = inputData[j] + " (" + str(marketPrice) + " USD)"

    return inputData

def bitlyUrl(url):
    # post_url = 'https://api-ssl.bitly.com/v3/shorten?access_token={token}&longUrl={url}'.format(
    #     token='9d6490b11c965cbafcd0c3c6e239837825aaa4b5',
    #     url=url
    # )
    # res = requests.get(post_url)
    # if res.status_code == 200:
    #     return res.json().get('data').get('url')
    # else:
    #     return url
    
    return url

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
                                            optional = True),
            requirements.BooleanRequirement(name = 'mnemonic',
                                            description = "mnemonic",
                                            default = False,
                                            optional = True)
            ,
            requirements.BooleanRequirement(name = 'pdf',
                                            description = "export pdf",
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

                mnemonic_reg = re.compile('[a-z]{3,8}')
                exr = re.compile('[\\\\n]?[a-zA-Z]{3,8}\\\\n[a-zA-Z]{3,8}\\\\n[a-zA-Z]{3,8}\\\\n[a-zA-Z]{3,8}\\\\n[a-zA-Z]{3,8}\\\\n[a-zA-Z]{3,8}\\\\n[a-zA-Z]{3,8}\\\\n[a-zA-Z]{3,8}\\\\n[a-zA-Z]{3,8}\\\\n[a-zA-Z]{3,8}\\\\n[a-zA-Z]{3,8}\\\\n[a-zA-Z]{3,8}\\\\n[a-zA-Z]{3,8}\\\\n[a-zA-Z]{3,8}\\\\n[a-zA-Z]{3,8}\\\\n[a-zA-Z]{3,8}\\\\n[a-zA-Z]{3,8}\\\\n[a-zA-Z]{3,8}\\\\n[a-zA-Z]{3,8}\\\\n[a-zA-Z]{3,8}\\\\n[a-zA-Z]{3,8}\\\\n[a-zA-Z]{3,8}\\\\n[a-zA-Z]{3,8}\\\\n[a-zA-Z]{3,8}')
                address_count = 0
                tx_count = 0

                duplicated_str = []
                printed_str = []
                check_pdf_list = []

                transaction_list = []
                rippple_transaction_list = []
                
                

                d = enchant.PyPWL("wordlist.txt")
                
                backup_offset = 0
                backup_mapped_offset = 0
                backup_mapped_size = 0

                check_error = 0
                t_backup_offset = 0
                t_backup_mapped_offset = 0
                t_backup_mapped_size = 0

                for mapval in proc_layer.mapping(0x0, proc_layer.maximum_address, ignore_errors = True):
                    offset, size, mapped_offset, mapped_size, maplayer = mapval
                    #print(mapval)
                    ripple_recv_list = []
                    btc_recv_list = []
                    eth_recv_list = []
                    
                    mnemonic_list = []
                    mnemonic_count = 0
                    file_output = "Disabled"
                    
                    try:
                        data = proc_layer.read(offset, size, pad = True)
                        #file_data.write(data) --> mnemonic
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
                                if 'address' in buf and 'bitcoin' in buf:
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
                        
                            if self.config['mnemonic']:
                                '''
                                if mnemonic_reg.search(str(data)):
                                    for j in mnemonic_reg.findall(str(data)):
                                        if j not in mnemonic_list:
                                            mnemonic_list.append(j)
                                    
                                    for word in mnemonic_list:
                                        #print(word)
                                        check_word = word.replace('\n','')
                                        if d.check(check_word.lower()):
                                            mnemonic_count += 1
                                            
                            if mnemonic_count >= 20:
                                print(mnemonic_list) '''
                                            
                                                
                                    

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
                                            check_pdf_list.append('xrp')

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
                                        #time.sleep(10)
                                        
                                        ua = UserAgent(verify_ssl=False)
                                        userAgent = ua.random
                                        
                                        headers = {'User-Agent': userAgent}
                                        res = requests.get('https://chain.api.btc.com/v3/address/'+ad,headers=headers)
                                        try:
                                            #print(res.text)
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

                                        except:
                                            check_error = 1
                                            

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
                    
            if self.config['mnemonic']:
                pid_buf = open("pid.{}.dmp".format(pid),'rb')
                #w_list = open('wordlist.txt','r')
                size = os.path.getsize("pid.{}.dmp".format(pid))
                dup = []
                
                while True:
                    pid_data = pid_buf.read(1024)
                    pid_data_ascii = ''
                    
                    for i in pid_data:
                        pid_data_ascii += chr(i)
                    pid_data_ascii = re.sub(r'[^\x00-\x7F]+',' ', pid_data_ascii)
                    
                    #pid_data_str = strings = re.findall(r'\w+', pid_data)
                    check_count = 0
                    mnemonic_word = []
                    if not pid_data:
                        break
                    
                    '''
                    if 'vacant' in pid_data_ascii:
                        print(pid_data_ascii)
                '''

                    if mnemonic_reg.search(pid_data_ascii):
                        for i in mnemonic_reg.findall(pid_data_ascii):
                            if d.check(i):
                                if not i in mnemonic_word:
                                    mnemonic_word.append(i)
                                else:
                                    break
                                
                    if len(mnemonic_word) >= 24:
                        print('mnemonic word list')
                        print(mnemonic_word)
                            
                        
                            
                            

                        
                      
                            
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
                                        #time.sleep(10)
                                        headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36'}
                                        res = requests.get('https://chain.api.btc.com/v3/tx/'+transaction, headers=headers)
                                        result = json.loads(json.dumps(res.json()))
                                        creation_time = str(result.get('data').get('created_at'))
                                        str_time = time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(int(creation_time)-time.timezone))
                                        sender = result.get('data').get('inputs')[0].get('prev_addresses')[0]
                                        recipient = result.get('data').get('outputs')[1].get('addresses')[0]
                                        amount = str(result.get('data').get('inputs_value'))
                                        yield (0, (transaction,str_time,sender,recipient,amount))
                                    except:
                                        check_error = 1
            
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

                try:
                    check_pdf_list.insert(0,str(address_count))
                    check_pdf_list.insert(1,str(tx_count))
                    #print(check_pdf_list)
                except:
                    print('')
            
            encoding = 0
            
            if self.config['pdf']:
                test_pdf_list = ['4', '4', 'rUNzcGi4eZUmEcprhmAAKto4fTJLsNQBEb', '0', 'XRP', 'raQwCVAJVqjrVm1Nj5SFRcX8i22BhdC9WA', '5711.005117', 'XRP', 'rshRbDTDVUA38vQxax9T7jBC1Bb3H7xQTR', '0', 'XRP', 'rHuULof8mk1m7wffrmsBAVB3g6yAHivbmQ', '0', 'XRP', '31A88C6685422785FF6C7CB2A768AEA918D2E9D6BFA9218E438B64E0A1D78A32', '2021-10-09T11:56:01.000Z', 'rUNzcGi4eZUmEcprhmAAKto4fTJLsNQBEb', 'raQwCVAJVqjrVm1Nj5SFRcX8i22BhdC9WA', '10000000', '5A86F9D6820264B34F8801FA36C6C45DC72FFBEF02FBFA2EDAA9C33FC10B2AF0', '2021-09-25T04:32:10.000Z', 'rshRbDTDVUA38vQxax9T7jBC1Bb3H7xQTR', 'rUNzcGi4eZUmEcprhmAAKto4fTJLsNQBEb', '9995000', 'ECFA57394ADF5570F836BDFFA47385324BA66FF8BED3EB94D2035F18D7524B33', '2021-09-25T04:19:42.000Z', 'rUNzcGi4eZUmEcprhmAAKto4fTJLsNQBEb', 'rshRbDTDVUA38vQxax9T7jBC1Bb3H7xQTR', '30000000', '1F67F10BCB4396D8B905A0F4936E8166F34CECFF4975C3FC290956035C48FC98', '2021-09-25T01:55:21.000Z', 'rHuULof8mk1m7wffrmsBAVB3g6yAHivbmQ', 'rUNzcGi4eZUmEcprhmAAKto4fTJLsNQBEb', '40670000']

                test_pdf_list = setNumFormat(test_pdf_list)
                inputAddrCount = int(test_pdf_list[0])
                inputTxCount = int(test_pdf_list[1])

                addrTableData = [['Address', 'Balance (USD)', 'Type']]
                txTableData = [['Tag', 'Value']]    
                txLinkData = [['Num', 'Link']]

                setDoc(inputAddrCount, inputTxCount, addrTableData, txTableData, txLinkData, test_pdf_list)
                print("COMPLETE")


    
    def run(self):
        filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])

        return renderers.TreeGrid([("      Virtual", str), ("  Physical", str),
                                   ("  Size", str), ("Address", str),(' '*40+"Balance", str)],
                                  self._generator(
                                      pslist.PsList.list_processes(context = self.context,
                                                                   layer_name = self.config['primary'],
                                                                   symbol_table = self.config['nt_symbols'],
                                                                   filter_func = filter_func)))