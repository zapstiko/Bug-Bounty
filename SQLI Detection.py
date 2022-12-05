from burp import IBurpExtender
from burp import IHttpListener

class BurpExtender(IBurpExtender, IHttpListener):

  def registerExtenderCallbacks(self, callbacks):
    # Set up extension
    self._callbacks = callbacks
    self._helpers = callbacks.getHelpers()
    callbacks.setExtensionName("SQL Injection Detector")
    callbacks.registerHttpListener(self)

  def processHttpMessage(self, toolFlag, messageIsRequest, currentRequest):
    # Only process requests
    if not messageIsRequest:
      return

    # Get the request URL
    requestInfo = self._helpers.analyzeRequest(currentRequest)
    url = requestInfo.getUrl()

    # Check if the URL is vulnerable to SQL injection
    if check_injection(url):
      print("[!] SQL injection detected in request to %s" % url)

def check_injection(url):
  # Try injecting a single quote into the URL
  injection_url = url + "'"
  r = requests.get(injection_url)

  # If the response contains an error message, it may be vulnerable to SQL injection
  if "SQL" in r.text or "syntax" in r.text:
    return True
  else:
    return False
