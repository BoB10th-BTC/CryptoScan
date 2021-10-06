# -*- coding: utf-8 -*-
import re
import os

eth_reg = re.compile(r'^0x[a-fA-F0-9]{40}$')
btc_reg = re.compile(r'^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$')
json = re.compile(r'\{.*\:\{.*\:.*\}\}') #json
ripple_reg = re.compile(r'r[0-9a-zA-Z]{33,35}')

eth_list = []
btc_list = []
ripple_list = []

f_name = '수신.raw'

with open(f_name,'rb') as mem:
    btc_recv_list = []
    eth_recv_list = []
    ripple_recv_list = []

    while True:
        read = mem.read(10000)
        print("offset : 0x%x"%int(mem.tell()))

        if mem.tell() == os.path.getsize(f_name):
            break

        text = ''
        for i in read:
                text = text + chr(i)
    
        for i in range(1):

            if json.search(text):
                if eth_reg.search(text):
                    for j in eth_reg.findall(text):
                        if j not in eth_recv_list: 
                            eth_recv_list.append(j) 

                if btc_reg.search(text):
                    for j in btc_reg.findall(text):
                        btc_list.append(j)

                #print(text)
                for j in ripple_reg.findall(text): 
                    if j not in ripple_recv_list: 
                        ripple_recv_list.append(j)
                #print(eth_recv_list) 
                #print(ripple_recv_list)
                break
print(eth_recv_list) 
print(ripple_recv_list)