//A generic proxy.pac for those not wanting to reconfigure anything
//By Singe at Sensepost

function FindProxyForURL(url, host) {

//-------------------------------------------------//
	// Define proxies we will be using

	//Googlesharing proxie, replace with your own if you're running a GoogleSharing.net proxy
	var proxy_GoogleSharing = "PROXY googlesharing.net:80";

	//Blackhole, ideally replace this with your own
	var proxy_BlackHole = "PROXY singe.za.net:8085;";

	//Normal behaviour, DIRECT for no proxy, PROXY host:port or SOCKS host:port
	var normal = "DIRECT";

	//Normalize host and url
	url = url.toLowerCase();
	host = host.toLowerCase();

//-------------------------------------------------//
	// Check for internal hosts

	//A host with no .'s (isPlainHostName) is internal
	//RFC 1918 addresses are internal
	//Hosts ending in .local are internal

	if ( isPlainHostName(host) ||
		 shExpMatch(host, "*.local") ||
		 isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
		 isInNet(dnsResolve(host), "192.168.0.0", "255.255.255.0") ||
		 isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ) {
		return "DIRECT";
	}

//-------------------------------------------------//
	//Googlesharing
	if (shExpMatch(host,"*google.*")) {
		return proxy_GoogleSharing;
	}

//-------------------------------------------------//
	//Blackhole trackers, this needs beefing up
	if ( shExpMatch(host,"*googlesyndication.*")
		 || shExpMatch(host,"*googleadservices.*")
		 || shExpMatch(host,"*google-analytics.*")
		 || shExpMatch(url,"*facebook.com/plugins/like.php*")
		 || shExpMatch(url,"*facebook.com/plugins/likebox.php*")
	   ) {
		return proxy_BlackHole;
	}

//-------------------------------------------------//
	//Default behaviour
	return normal;

} //end FindProxyForURL
