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
        self.drawImage(r"bob.jpg",x=img_x, y=img_y, width=width, height=height, preserveAspectRatio=True)

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

        # 중복 코드
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
                [('ALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                 ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                 ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.lightgrey),
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
                [('ALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                 ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                 ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.lightgrey),
                 ('LINEBELOW', (0, 0), (-1, 0), 1, colors.black),
                 ('OUTLINE', (0, 0), (-1, -1), 1, colors.lightgrey),
                 ('LEFTPADDING', (0, 0), (-1, -1), 1),
                 ('RIGHTPADDING', (0, 0), (-1, -1), 1),
                 ('TOPPADDING', (0, 0), (-1, -1), 1),
                 ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
                 ])

        txLink.setStyle(txLinkStyle)
        self.elements.append(Paragraph(str("More at BTC.COM"), styles['Heading2']))
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

    def createReport(self, data, widths):
        if(data==addrTableData):
            self.createAddrTable(data, widths)
        elif(data==txTableData):
            self.createTxTable(data, widths)
        elif(data==txLinkData):
            self.createTxLink(data, widths)    
        self.elements.append(Spacer(0, inch * 0.05))

def getAddr(inputData):
    res = []    
    for k in range(2, (inputAddrCount)*3+2, 3):    
        res += inputData[k], inputData[k+1], inputData[k+2]
    return res

def getTx(inputData):
    res = []
    for k in range((inputAddrCount)*3+2, len(inputData), 5):
        res += inputData[k], inputData[k+1], inputData[k+2], inputData[k+3], inputData[k+4]
    return res

def setDoc(inputAddrCount, inputTxCount, addrTableData, txTableData, txLinkData):
    # 보고서 제목
    doc_title = "CryptoScan Report"
    test = BaseReport(doc_title, make_landscape=True)

    # 보고서 정보
    summary = {
        'Report Name': 'CryptoScan_' + time.strftime('%m%d'),
        'Report Created': datetime.now().astimezone(pytz.timezone('Asia/Seoul')),
        'Analysis Version': '1.0'
    }
    # 테이블 데이터 집어넣기
    for i in range(inputTxCount):
        txTableData+=([['TXID'], ['Time'], ['Sender'], ['Receiver'], ['Amount']])
    
    for i in range(0, inputAddrCount * 3, 3): # 12
        val1 = [getAddr(inputData)[i], getAddr(inputData)[i+1], getAddr(inputData)[i+2]]
        addrTableData.append(val1)

    for j in range(0, inputTxCount*5): # 20
        txTableData[j+1].append(getTx(inputData)[j])


            
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

    test.createSummary(summary)
    test.createReport(addrTableData, ['50%', '43%', '7%'])
    test.createReport(txTableData, ['20%', '80%'])
    test.createReport(txLinkData, ['10%', '90%'])

    test.buildDocument(r'Cryptoscan_Report.pdf')

def setNumFormat(inputData):
    # 숫자 콤마
    for i in range(1, int(inputData[1]) + 1):
        idx = 1 + int(inputData[0]) * 3 + 5 * i
        inputData[idx] = format(int(inputData[idx]), ',')
    # 코인 market price 반영
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
    
    

if __name__ == "__main__":  # pragma: no cover

    inputData = ['4', '4', 'rUNzcGi4eZUmEcprhmAAKto4fTJLsNQBEb', '0', 'XRP', 'raQwCVAJVqjrVm1Nj5SFRcX8i22BhdC9WA', '5711.005117', 'XRP', 'rshRbDTDVUA38vQxax9T7jBC1Bb3H7xQTR', '0', 'XRP', 'rHuULof8mk1m7wffrmsBAVB3g6yAHivbmQ', '0', 'XRP', '31A88C6685422785FF6C7CB2A768AEA918D2E9D6BFA9218E438B64E0A1D78A32', '2021-10-09T11:56:01.000Z', 'rUNzcGi4eZUmEcprhmAAKto4fTJLsNQBEb', 'raQwCVAJVqjrVm1Nj5SFRcX8i22BhdC9WA', '10000000', '5A86F9D6820264B34F8801FA36C6C45DC72FFBEF02FBFA2EDAA9C33FC10B2AF0', '2021-09-25T04:32:10.000Z', 'rshRbDTDVUA38vQxax9T7jBC1Bb3H7xQTR', 'rUNzcGi4eZUmEcprhmAAKto4fTJLsNQBEb', '9995000', 'ECFA57394ADF5570F836BDFFA47385324BA66FF8BED3EB94D2035F18D7524B33', '2021-09-25T04:19:42.000Z', 'rUNzcGi4eZUmEcprhmAAKto4fTJLsNQBEb', 'rshRbDTDVUA38vQxax9T7jBC1Bb3H7xQTR', '30000000', '1F67F10BCB4396D8B905A0F4936E8166F34CECFF4975C3FC290956035C48FC98', '2021-09-25T01:55:21.000Z', 'rHuULof8mk1m7wffrmsBAVB3g6yAHivbmQ', 'rUNzcGi4eZUmEcprhmAAKto4fTJLsNQBEb', '40670000']
    inputData = setNumFormat(inputData)

    inputAddrCount = int(inputData[0])
    inputTxCount = int(inputData[1])
    
    addrTableData = [['Address', 'Balance (USD)', 'Type']]
    txTableData = [['Tag', 'Value']]    
    txLinkData = [['Number', 'Link']]

    setDoc(inputAddrCount, inputTxCount, addrTableData, txTableData, txLinkData)

    print("EXPORTED")