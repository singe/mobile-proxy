#!/usr/bin/env python
# Scalable blachole server to be used with proxy.pac for WebKit browsers
# Original by Gert at Sensepost, modified by Singe at Sensepost

import time, os, pwd, grp

from twisted.protocols import basic, policies
from twisted.internet import protocol, reactor

PORT=8085
PAYLOAD = """HTTP/1.0 200 OK\r\nDate: %s\r\nServer: Blackhole\r\nStatus: 200 OK\r\nContent-Type: text/html;\r\nConnection: close\r\n\r\n"""
TIMEOUT=5 #In seconds to receive the WHOLE request

#OSX uses negative UID/GIDs, which are supposed to be offsets from
#UINT32_MAX (2^32), which python 2.7.1's os.set(u|g)ui find to be an overflow.
#Hence the error checking below.
def safe_setgid(running_gid):
	try:
		os.setgid(running_gid)
	except OSError, e:
		print('Could not set effective group id: %s' % e)

def safe_setuid(running_uid):
	try:
		os.setuid(running_uid)
	except OSError, e:
		print('Could not set effective group id: %s' % e)

# Taken from http://antonym.org/2005/12/dropping-privileges-in-python.html
def drop_privileges(uid_name='nobody', gid_name='nogroup'):
	starting_uid = os.getuid()
	starting_gid = os.getgid()
	starting_uid_name = pwd.getpwuid(starting_uid)[0]

	if os.getuid() != 0:
		# We're not root so, like, whatever dude
		print("drop_privileges: already running as '%s'"%starting_uid_name)
		return

	# If we started as root, drop privs and become the specified user/group
	if starting_uid == 0:
		# Get the uid/gid from the name
		running_uid = pwd.getpwnam(uid_name)[2]
		running_gid = grp.getgrnam(gid_name)[2]

		# Try setting the new uid/gid
		try:
			safe_setgid(running_gid)
		except OverflowError, e:
			if (running_gid > 4294967290):
				running_gid = -4294967296 + running_gid
				safe_setgid(running_gid)

		try:
			safe_setuid(running_uid)
		except OverflowError, e:
			if (running_uid > 4294967290):
				running_uid = -4294967296 + running_uid
				safe_setuid(running_gid)

		# Ensure a very convervative umask
		new_umask = 077
		old_umask = os.umask(new_umask)
		print('drop_privileges: Old umask: %s, new umask: %s' % (oct(old_umask), oct(new_umask)))

	final_uid = os.getuid()
	final_gid = os.getgid()
	print('drop_privileges: running as %s/%s' % (pwd.getpwuid(final_uid)[0],grp.getgrgid(final_gid)[0]))

class BlackHoleHttpProtocol(basic.LineReceiver, policies.TimeoutMixin):
    def connectionMade(self):
        self.setTimeout(TIMEOUT)

    def timeoutConnection(self):
        self.dump_payload()

    def lineReceived(self, line):
        if line == '':
            self.dump_payload()

    def connectionLost(self, reason):
        self.setTimeout(None)

    def date_time_string(self, timestamp=None):
        """Return the current date and time formatted for a message header."""

        weekdayname = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        monthname = [None,
                 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

        if timestamp is None:
            timestamp = time.time()
        year, month, day, hh, mm, ss, wd, y, z = time.gmtime(timestamp)
        s = "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (
                weekdayname[wd],
                day, monthname[month], year,
                hh, mm, ss)
        return s

    def dump_payload(self):
        self.transport.write(PAYLOAD % self.date_time_string())
        self.transport.loseConnection()


class BlackHoleHttpFactory(protocol.ServerFactory):
    protocol = BlackHoleHttpProtocol

print "Dropping privs"
drop_privileges()
print "Starting reactor"
reactor.listenTCP(PORT, BlackHoleHttpFactory())
reactor.run()
