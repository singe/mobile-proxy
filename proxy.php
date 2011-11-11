//A dynamic proxy.pac for those wanting to reconfigure something
//By Singe at Sensepost
<?php
	#header("Content-type: application/x-ns-proxy-autoconfig");
?>
function FindProxyForURL(url, host) {

//-------------------------------------------------//
	// Define proxies we will be using

	//Googlesharing proxie, replace with your own if you're running a GoogleSharing.net proxy
	var proxy_GoogleSharing = "PROXY proxy.googlesharing.net:80";

	//Blackhole, ideally replace this with your own
	var proxy_BlackHole = "PROXY singe.za.net:8085;";

	//Normal behaviour, DIRECT for no proxy, PROXY host:port or SOCKS host:port
	<?php
		$type = "PROXY";
		if ( isset($_REQUEST['proxy']) ) {
			if ( isset($_REQUEST['socks']) ) {
				$type = "SOCKS";
			}
			print 'var normal = "' . $type . ' ' . urlencode($_REQUEST['proxy']). ':' . urlencode($_REQUEST['port']) . '";';
		} else {
			print 'var normal = "DIRECT";';
		}
	?>


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
		 || shExpMatch(host,"*admob.com")
		 || shExpMatch(host,"*googleadservices.*")
		 || shExpMatch(host,"*google-analytics.*")
		 || shExpMatch(url,"*facebook.com/plugins/like.php*")
		 || shExpMatch(url,"*facebook.com/plugins/likebox.php*")
		 || shExpMatch(url,"*singe.za.net/blocktest.html*")
	   ) {
		return proxy_BlackHole;
	}

//-------------------------------------------------//
	//Default behaviour
	return normal;

} //end FindProxyForURL
