#!/usr/bin/python
# -*- coding: utf-8 -*-
# File name: palo-url-guncelleyici.py
# Author: Koray YILMAZ
# Date created: 29/07/2015
# Date last modified: 02/10/2015
# Version: 8
# Python Version: 2.7.5
# Description: parses the url in the url and updates the
#              custom-url-category element with this data
#              via pan.xapi
# Requirement: https://github.com/kevinsteves/pan-python

# -*- coding: utf-8 -*-
from __future__ import print_function
from xml.dom import minidom
from xml.dom.minidom import Document
import urllib2
import sys
import os
import time
import pan.xapi
import pan.commit
import datetime
import smtplib
from email.mime.text import MIMEText

options = {
        'delete': False,
        'edit': False,
        'get': False,
        'keygen': False,
        'show': False,
        'set': False,
        'dynamic-update': False,
        'commit': False,
        'validate': False,
        'force': False,
        'partial': [],
        'sync': False,
        'vsys': [],
        'commit_all': False,
        'ad_hoc': None,
        'modify': False,
        'op': None,
        'export': None,
        'log': None,
        'src': None,
        'dst': None,
        'move': None,
        'rename': False,
        'clone': False,
        'override': False,
        'api_username': None,
        'api_password': None,
        'hostname': None,
        'port': None,
        'serial': None,
        'group': None,
        'merge': False,
        'nlogs': None,
        'skip': None,
        'filter': None,
        'interval': None,
        'job_timeout': None,
        'stime': None,
        'pcapid': None,
        'api_key': None,
        'cafile': None,
        'capath': None,
        'print_xml': True,
        'print_result': True,
        'print_python': False,
        'print_json': False,
        'print_text': False,
        'cmd_xml': False,
        'pcap_listing': False,
        'recursive': False,
        'use_http': False,
        'use_get': False,
        'debug': 0,
        'tag': None,
        'xpath': None,
        'element': None,
        'cmd': None,
        'timeout': None,
        'version' : None,
        }



def print_status(xapi, action, exception_msg=None, logfp=sys.stderr):
    print(action, end='', file=logfp)
    if xapi.status_code is not None:
        code = ' [code=\"%s\"]' % xapi.status_code
    else:
        code = ''
    if xapi.status is not None:
        print(': %s%s' % (xapi.status, code), end='', file=logfp)
    if exception_msg is not None and exception_msg:
        print(': "%s"' % exception_msg.rstrip(), end='', file=logfp)
    elif xapi.status_detail is not None:
        print(': "%s"' % xapi.status_detail.rstrip(), end='', file=logfp)
    print(file=logfp)
    return xapi.status


def get_response(xapi):
    if options['print_xml']:
        if options['print_result']:
            s = xapi.xml_result()
        else:
            s = xapi.xml_root()
        if s is not None:
            return s.lstrip('\r\n').rstrip()

    if options['print_python'] or options['print_json']:
        d = xml_python(xapi, options['print_result'])
        if d:
            if options['print_python']:
                return 'var1 =', pprint.pformat(d)
            if options['print_json']:
                return json.dumps(d, sort_keys=True, indent=2)

    if options['print_text'] and xapi.text_document is not None:
        return xapi.text_document

def str_rep(str):
    new_str = str.strip()
    new_str = new_str.replace('http://','')
    new_str = new_str.replace('/','')
    return new_str

def get_usomlist(url):
    # get the malicious urls from the url db
    #'https://www.usom.gov.tr/url-list.xml'
    file = urllib2.urlopen(url)
    data = file.read()

    # parse string
    xmldoc = minidom.parseString(data)
    itemlist = xmldoc.getElementsByTagName('url')

    # get the url values in the tree
    usomlist=[]
    for item in itemlist:
        usomlist.append(str_rep(item.firstChild.nodeValue))

    return usomlist

def paloxml_to_list(data,leaf_name):
    # parse string
    xmldoc = minidom.parseString(data)
    itemlist = xmldoc.getElementsByTagName(leaf_name)

    palolist = []
    for item in itemlist:
        palolist.append(str(item.firstChild.nodeValue))
    return palolist

'''
    return:
    <list>
    <member>usom_list[0]</member>
    <member>usom_list[1]</member>
    <member>usom_list[2]</member>
    </list>
'''
def list_to_paloxml(ulist):
    doc = Document()
    declaration = doc.toxml()
    root = doc.createElement('list')
    doc.appendChild(root)
    for item in ulist:
        main = doc.createElement('member')
        root.appendChild(main)
        domain = doc.createTextNode(str(item))
        main.appendChild(domain)
    xml = doc.toprettyxml(indent=' ')[(len(declaration) + 1):]
    return xml

def get_current_url_categories(xapi):
    action = 'show'
    xapi.show(xpath=options['xpath'],
                      extra_qs=options['ad_hoc'])
    print_status(xapi, action)   
    xmlres = get_response(xapi)
    return xmlres

def get_palo_software_version(xapi):
    action = 'op'
    cmd = "<show><system><info></info></system></show>"
    xapi.op(cmd=cmd)
    print_status(xapi, action)
    xmlres = get_response(xapi)
    xml_sysinfo_palo = xmlres.replace('\n','')
    print("sysinfo: ", xml_sysinfo_palo)
    palo_version = paloxml_to_list(xml_sysinfo_palo,'sw-version')[0]
    return palo_version

def palo_commit(xapi, xpath, element, logfp):
    try:
        xapi.edit(xpath=xpath,
                  element=element)
    except pan.xapi.PanXapiError as msg:
        print('edit:', msg, file=logfp)
        sys.exit(1)

    #validate safhasi
    if options['version'] == 6:
        c = pan.commit.PanCommit(force=False,
                                 commit_all=False,
                                 merge_with_candidate=False)
        cmd = c.cmd()
        kwargs = {
            'cmd': cmd,
            'sync': False,
            'interval': None,
            'timeout': None,
            }
        action = 'commit'
        xapi.commit(**kwargs)
        res = print_status(xapi, action)
        if "success" in res:
            print('Validate OK. Continue.', file=logfp)
        else:
            print('Validate not OK. Exit!', file=logfp)
            sys.exit(1)
        print('Waiting for the 30 sec to validation commit to complete...', file=logfp)
        #TODO: pan xapiden donulen degere gore beklemeli sonsuz
        time.sleep(30)
    else:
        print(options['version'], "icin validate kodu eklenecek", logfp)
    #commit safhasi

    cmd = "<commit></commit>"
    kwargs = {
                    'cmd': cmd,
                    'sync': options['sync'],
                    'interval': options['interval'],
                    'timeout': options['job_timeout'],
                    }
    action = 'commit'
    xapi.commit(**kwargs)
    print_status(xapi, action)
    print('Commit gonderildi!', file=logfp)

def main():
    # constants for your configuration
    # TODO: edit
    PALO_FW_TAG = 'fw-bsk'
    CATEGORY_NAME = 'usom_zararli'
    USOM_ZARARLILAR = 'https://www.usom.gov.tr/url-list.xml'
    SMTP_SERVER_NAME = 'mail.bilgi.tubitak.gov.tr'

    
    filepath = os.path.dirname(os.path.abspath('__file__'))
    if len(sys.argv) == 1:
        print("Kullanim: ./palo-url-guncelleyici.py <credentials tag filename> <opsiyonel: domain>")
        sys.exit(1)
    
    if len(sys.argv) >= 2:
        PALO_FW_TAG = sys.argv[1]
    
    today = datetime.datetime.now()
    log_file_name = PALO_FW_TAG + "_" + today.strftime('%Y%m%d-%H%M') + ".log"
    
    
    logfp = open(os.path.join(filepath, log_file_name), 'a+')
    
    try:
        xapi = pan.xapi.PanXapi(tag=PALO_FW_TAG)
    except pan.xapi.PanXapiError as msg:
        print('pan.xapi.PanXapi:', msg, file=logfp)
        sys.exit(1)

    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/custom-url-category/"
    xpath += "entry[@name='" + CATEGORY_NAME + "']/list"

    options['xpath'] = xpath
    #print(xpath)

    #USOM'un yayınladığı domain listesini getir
    usomlist = get_usomlist(USOM_ZARARLILAR)
    
    #manuel ekleme
    if len(sys.argv) == 3:
        usomlist.append(str_rep(sys.argv[2]))

    diff_urllist = []

    #Listeyi palo alto element xml e dönüştür
    usomxml = list_to_paloxml(usomlist)

    xml_urlcat_palo = get_current_url_categories(xapi)
    print("Su anki kategoriler: ",xml_urlcat_palo)
    current_cust_category_list = paloxml_to_list(xml_urlcat_palo,'member')
    
    #palo versiyonu al
    sw_version =  get_palo_software_version(xapi)   
    print("Versiyon:", sw_version)
    version_base = sw_version.split('.')[0]
    options['version'] = version_base

    #USOM listesindeki ogeler Palo alto'da yoksa ekle
    cnt = 0
    for item in usomlist:
        if not item in current_cust_category_list:
            cnt += 1
            print(str(item))
            diff_urllist.append(str(item))
            current_cust_category_list.append(str(item))
    if cnt == 0:
        print("USOM veri tabani ile bu Palo Alto guncel!")
        logfp.close() 
        sys.exit(0)
    
    print(cnt,"adet yeni oge geldi", file=logfp)
    print('\n'.join(diff_urllist), file=logfp)
    updated_categories_xml = list_to_paloxml(current_cust_category_list)

    
    #dosyaya url leri yaz
    fl  = open(os.path.join(filepath, CATEGORY_NAME + ".xml"), 'w')
    fl.write(updated_categories_xml)
    fl.close()

    #xmlfile = open(os.path.join(filepath, CATEGORY_NAME + ".xml"),'r')
    #element = xmlfile.read()
    #xmlfile.close()
    element = updated_categories_xml
    
    
    #print(xml_urlcat_palo)
    
    #commit oncesi hazirliklar
    palo_commit(xapi, xpath, element, logfp)
    logfp.close()
    fp = open(os.path.join(filepath, log_file_name), 'rb')
    #send results to smtp server
    msg = MIMEText(fp.read())
    fp.close()
    msg['Subject'] = PALO_FW_TAG + ' custom url category update script log' + log_file_name
    msg['From'] = 'admin@tubitak.gov.tr'
    msg['To'] = 'sdestek@tubitak.gov.tr'
    s = smtplib.SMTP(SMTP_SERVER_NAME)
    s.sendmail(msg['From'],msg['To'],msg.as_string())
    
    

if __name__ == '__main__':
    main()
