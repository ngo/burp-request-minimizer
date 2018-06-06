from burp import IBurpExtender, IContextMenuFactory, IContextMenuInvocation
from burp import IParameter
from javax.swing import JMenuItem
from threading import Thread
from functools import partial
import time

IGNORED_INVARIANTS = set(['last_modified_header'])

class Minimizer(object):
    def __init__(self, callbacks, request):
        self._cb = callbacks
        self._helpers = callbacks.helpers
        self._request = request[0]
        self._httpServ = self._request.getHttpService()

    def compare(self, etalon, response, etalon_invariant):
        invariant = set(self._helpers.analyzeResponseVariations([etalon, response]).getInvariantAttributes())
        print("Invariant", invariant)
        print("diff", set(etalon_invariant) - set(invariant))
        return len(set(etalon_invariant) - set(invariant)) == 0

    def minimize(self, replace, event):
        Thread(target=self._minimize, args=(replace,)).start()

    def _fix_cookies(self, current_req):
        """ Workaround for a bug in extender,
        see https://support.portswigger.net/customer/portal/questions/17091600
        """
        cur_request_info = self._helpers.analyzeRequest(current_req)
        new_headers = []
        rebuild = False
        for header in cur_request_info.getHeaders():
            if header.strip().lower() != 'cookie:':
                new_headers.append(header)
            else:
                rebuild = True
        if rebuild:
            return self._helpers.buildHttpMessage(new_headers, current_req[cur_request_info.getBodyOffset():])
        return current_req


    def _minimize(self, replace):
        try:
            request_info = self._helpers.analyzeRequest(self._request)
            current_req = self._request.getRequest()
            etalon = self._cb.makeHttpRequest(self._httpServ, current_req).getResponse()
            etalon2 = self._cb.makeHttpRequest(self._httpServ, current_req).getResponse()
            invariants = set(self._helpers.analyzeResponseVariations([etalon, etalon2]).getInvariantAttributes())
            invariants -= IGNORED_INVARIANTS
            print("Request invariants", invariants)
            for param in request_info.getParameters():
                print("Trying", param.getType(), param.getName(), param.getValue())
                if param.getType() in [IParameter.PARAM_URL, IParameter.PARAM_BODY and IParameter.PARAM_COOKIE]:
                    req = self._helpers.removeParameter(current_req, param)
                    resp = self._cb.makeHttpRequest(self._httpServ, req).getResponse()
                    if self.compare(etalon, resp, invariants):
                        print("excluded:", param.getType(), param.getName(), param.getValue())
                        current_req = self._fix_cookies(req)
                else:
                    print("JSON and XML parameters are not currently supported")
            if replace:
                self._request.setRequest(current_req)
            else:
                self._cb.sendToRepeater(
                        self._httpServ.getHost(),
                        self._httpServ.getPort(),
                        self._httpServ.getProtocol() == 'https',
                        current_req,
                        "minimized"
                )
        except Exception as e:
            print(e)

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName("Request minimizer")
        callbacks.registerContextMenuFactory(self)
        self._callbacks = callbacks

    def createMenuItems(self, invocation):
        if invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            return [JMenuItem(
                        "Minimize in current tab",
                        actionPerformed=partial(
                            Minimizer(self._callbacks, invocation.getSelectedMessages()).minimize,
                            True
                        )
                   ),
                    JMenuItem(
                        "Minimize in a new tab",
                        actionPerformed=partial(
                            Minimizer(self._callbacks, invocation.getSelectedMessages()).minimize,
                            False
                        )
                   ),
            ]

