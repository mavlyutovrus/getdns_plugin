if ('undefined' == typeof(GetDNS)) {
    var GetDNS = {
        onLoad: function onLoad() {
            var listener = {} ;
            listener.onStartHeaders = function(){} ;
            listener.onEndAttachments = GetDNS.Analyze;
            gMessageListeners.push ( listener ) ;
        },
        Analyze: function() {
	    document.getElementById("verified_label").value = "";
            if (!gDBView || gDBView.numSelected != 1 ) {
                return;
	    }
            var length = {};    
            var messageArray = gDBView.getURIsForSelection(length);
            var messageUri = messageArray[0];
	    var messageHeaders = GetDNS.GetMsgHeaders(messageUri);
	    var domains = GetDNS.GetDomainsToCheck(messageHeaders);
	    GetDNS.CheckDomains(domains);
        },

	CheckDomains: function(domains) {
            var url = 'http://127.0.0.1:8085/?host=' + domains.join();
            var request = Components.classes["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance(Components.interfaces.nsIXMLHttpRequest);
            request.onload = function(aEvent) {
		var response = aEvent.target.responseText;
	        document.getElementById("verified_label").value = response;
		if (response.indexOf("Verified") > -1) {
		    document.getElementById("verified_label").className = "green";
		} else {
		    document.getElementById("verified_label").className = "red";
		}
            };
            request.onerror = function(aEvent) {
	        document.getElementById("verified_label").value = "Unknown result"; 
		document.getElementById("verified_label").className = "gray";
            };
            request.open("GET", url, true);
            request.send(null);
	},

	ExtractHeader: function(headerName, headers) {
	    var started = false;
	    var selected = "";
	    for (var lineIndex = 0; lineIndex < headers.length; ++lineIndex) {
		if (headers[lineIndex].indexOf(headerName) == 0) {
		    started = true;
                    selected += headers[lineIndex].replace(headerName + ":", "");
		    continue;
		}
		if (started) {
		    if (headers[lineIndex].indexOf(" ") == 0 || headers[lineIndex].indexOf("\t") == 0) {
			selected += headers[lineIndex];					
		    } else {
			break;
		    }
		}
	    }
	    return selected;
	},

	GetDomainsToCheck: function(headers) {
	    domains = [];
	    var authResults = GetDNS.ExtractHeader("Authentication-Results", headers);
	    var host = /dkim=pass\s+header\.i=@([^;\s\n]+)/.exec(authResults);
	    host = host ? host[1] : "";
	    if (host) {
		domains.push(host);
	    }
	    var dkimSignature = GetDNS.ExtractHeader("DKIM-Signature", headers);
	    host = /d=([^;\s\n]+)/.exec(dkimSignature);
	    host = host ? host[1] : "";
	    if (host && (!domains.length || domains[0] != host)) {
		domains.push(host);
	    }
	    if (!domains.length) {
		var spfDomain = /spf=[^\s]+ \(([^\s\n:;)]+)/.exec(authResults);
		if (spfDomain) {
		    domains.push(spfDomain[1]);
		}
	    }
	    return domains;
	},

        Dump: function (aMessage) {
            var consoleService = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);
            consoleService.logStringMessage("GETDNS: " + String(aMessage));
        },
        GetMsgBody: function (messageURI) {
	    try {
                var messenger = Components.classes["@mozilla.org/messenger;1"].createInstance(Components.interfaces.nsIMessenger);
                var aMessageHeader = messenger.messageServiceFromURI(messageURI).messageURIToMsgHdr(messageURI); 
                var listener = Components.classes["@mozilla.org/network/sync-stream-listener;1"].createInstance(Components.interfaces.nsISyncStreamListener);
                messenger.messageServiceFromURI(messageURI).streamMessage(messageURI, listener, null, null, false, "");
                var body = aMessageHeader.folder.getMsgTextFromStream(listener.inputStream, aMessageHeader.Charset, 65536, 32768, false, true, { });
                return  body;
	    } catch (ex) {
		GetDNS.Dump(ex);
		return "";
	    }
        },
        GetMsgHeaders: function (messageURI) {
            var messenger = Components.classes["@mozilla.org/messenger;1"].createInstance(Components.interfaces.nsIMessenger);
            var messageService = messenger.messageServiceFromURI(messageURI);
            var messageStream = Components.classes["@mozilla.org/network/sync-stream-listener;1"].createInstance(Components.interfaces.nsIInputStream);
            var inputStream = Components.classes["@mozilla.org/scriptableinputstream;1"].createInstance(Components.interfaces.nsIScriptableInputStream);
            inputStream.init(messageStream);
            try {
                messageService.streamMessage(messageURI,messageStream, null, null, false, null);
            } catch (ex) {
		GetDNS.Dump(ex);
		return "";
	    }
            var headers = "";
            try {
                while (inputStream.available()) {
                    headers = headers + inputStream.read(512);
                    var endPos = Math.max(headers.indexOf("\r\n\r\n"), headers.indexOf("\n\n"));
                    if (endPos > 0) {
                        headers = headers.substring(0, endPos);
                        break;
                    }
                }
            } catch(ex){
		GetDNS.Dump(ex);
		return "";
	    }
	    var headersAsArray = headers.replace("\r", "").split("\n");
            return headersAsArray;
        }
    };
}

window.addEventListener("load", function(e) {GetDNS.onLoad(e);}, false);
