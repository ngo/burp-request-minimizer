from burp import IBurpExtender, IContextMenuFactory, IContextMenuInvocation
from javax.swing import JMenuItem
from threading import Thread
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

    def minimize(self, event):
        Thread(target=self._minimize).start()

    def _minimize(self):
        try:
            request_info = self._helpers.analyzeRequest(self._request)
            current_req = self._request.getRequest()
            etalon = self._cb.makeHttpRequest(self._httpServ, current_req).getResponse()
            etalon2 = self._cb.makeHttpRequest(self._httpServ, current_req).getResponse()
            invariants = set(self._helpers.analyzeResponseVariations([etalon, etalon2]).getInvariantAttributes())
            invariants -= IGNORED_INVARIANTS
            print("Invariants", invariants)
            for param in request_info.getParameters():
                print("Trying", param.getType(), param.getName(), param.getValue())
                req = self._helpers.removeParameter(current_req, param)
                resp = self._cb.makeHttpRequest(self._httpServ, req).getResponse()
                if self.compare(etalon, resp, invariants):
                    print("excluded:", param.getType(), param.getName(), param.getValue())
                    current_req = req
            self._cb.sendToRepeater(self._httpServ.getHost(), self._httpServ.getPort(), self._httpServ.getProtocol() == 'https', current_req, "minimized")
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
                        "Minimize and send to repeater",
                        actionPerformed=Minimizer(self._callbacks, invocation.getSelectedMessages()).minimize
                   )]

