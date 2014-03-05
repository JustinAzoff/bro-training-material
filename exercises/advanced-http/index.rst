.. _url.pcap: http://www.bro.org/static/traces/url.pcap

========================================
Exercise: Advanced HTTP Traffic Analysis
========================================

.. class:: opening

    In this session we cover two more advanced use cases in the context of the
    HTTP protocol. The first part focuses on building a sidejacking detector
    and the second on creating tractable Bro data structures for web services.

Part 1: Building a Sidejacking Detector
=======================================

Sidejacking (or session hijacking) refers to an HTTP issue where an attacker
obtains a valid session cookie of a victim and uses it for impersonation. To
illustrate, consider the example where the victim Brody checks his latest
tweets at the local Starbucks hotspot while the attacker Brooke eavesdrop on
the wireless network from two seats behind. Brooke extracts the value of the
``Cookie`` header of all HTTP requests to ``twitter.com`` and uses it then for
her own requests to Twitter. Thus, she has hijacked Brody's Twitter session and
can now impersonate him.

The Firefox extension `Firesheep <http://codebutler.com/firesheep>`_ made
sidejacking available to the masses, without requiring the technical know-how
to conduct the above sketched steps manually. Network operators and incident
responders clearly would like to find out when their users' security and
privacy is compromised. So how can we detect this attack?

At a very basic level, we have to monitor each session cookie and observe
whether it appears in more than one user context. That is, if one IP address
uses a cookie previously used by another IP address, we have likely
witnessed a sidejacking incident.

A slightly weaker notion of sidejacking is what we call *session cookie reuse*,
i.e., reusing a cookie across different user agents, say Chrome and Firefox,
while the IP address remains the same. For simplicity reasons, we will only
focus on this notion in this exercise, but there is no conceptual difference
in the detection logic to the more general notion of sidejacking.

In practice, the detection is more complicated and `needs to handle a few more
corner cases`__. The full version of the detector addresses all of these issues
and can be downloaded from the `Bro scripts repository`__. There is another
caveat. Recently Firesheep `started using TLS for some services`__ (Google,
Twitter and Facebook) for the hijacked attacker connections, which prevents the
detection for these services entirely.

__ http://matthias.vallentin.net/blog/2010/10/taming-the-sheep-detecting-sidejacking-with-bro/
__ http://git.bro.org/bro-scripts.git
__ https://github.com/codebutler/firesheep/commit/9285c61689518d1e798d255d65e0eebcdc9ad725

.. exercise::
    Since the detection of sidejacking involves tracking session cookies, we
    need a way to access the cookie in the first place. Bro does not keep track
    of cookie values by default, so you need to extend it to do so. To this
    end, extend the ``HTTP::Info`` record with a field named ``cookie`` and
    fill in the value by writing a handler for the ``http_header`` event.

    You might find it helpful to use the provided script scaffold
    `reuse1.bro <reuse1.bro>`_. Adapt the script, run it on the trace
    `twitter.pcap <http://www.bro.org/static/traces/twitter.pcap>`_, and verify that the session cookies are
    logged successfully.

.. visible_solution::
    The file `reuse1-solution.bro <reuse1-solution.bro>`_ contains one possible
    solution.

    ::

	#separator \x09
	#set_separator	,
	#empty_field	(empty)
	#unset_field	-
	#path	http
	#open	2013-10-31-22-13-13
	#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	method	host	uri	referrer	user_agent	request_body_len	response_body_len	status_code	status_msg	info_code	info_msg	filename	tags	username	password	proxied	orig_fuids	orig_mime_types	resp_fuids	resp_mime_types	cookie
	#types	time	string	addr	port	addr	port	count	string	string	string	string	string	count	count	count	string	count	string	string	table[enum]	string	string	table[string]	vector[string]	vector[string]	vector[string]	vector[string]	string
	1320257579.121456	CucuIk2HsJymJ7RzL1	192.150.187.147	51731	199.59.149.230	80	1	GET	twitter.com	/	-	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.106 Safari/535.2	0	58603	200	OK	-	-	-	(empty)	-	-	-	-	-	FuUNzzwq3YtbqrYV2	text/html	__utmz=43838368.1308140498.28.11.utmcsr=nvie.com|utmccn=(referral)|utmcmd=referral|utmcct=/; __utma=43838368.1796737749.1282721850.1308140498.1308206467.29; __utmv=43838368.lang%3A%20en; guest_id=v1%3A13087319415918687; js=1; k=10.34.252.113.1320105621891535; original_referer=padhuUp37zi4XoWogyFqcGgJdw%2BJPXpx; auth_token=cceffe3d2d3edb25f9027b65c0bc4f54b23ec03d; twll=l%3D1320257295; lang=en; twid=u%3D403579461%7C1Rdt0%2FnmWmtcq3AHIcPk8%2BhHbh0%3D; _twitter_sess=BAh7DzoVaW5fbmV3X3VzZXJfZmxvdzA6DnJldHVybl90byJQaHR0cDovL3R3%250AaXR0ZXIuY29tL2FjY291bnQvY29uZmlybV9lbWFpbC9XdXJzdGZhY2h2ZXJr%250AdWYvQ0c3RDQtNUNGQzctMTMyMDI1Og9jcmVhdGVkX2F0bCsIEMN2ZTMBOgl1%250Ac2VyaQRFIg4YOgxjc3JmX2lkIiVkZTdkZjhkYzBiYzJkYzRkMDc5M2E0YjEz%250AZjc1MmYyOToHdWEwOhNwYXNzd29yZF90b2tlbiItY2NlZmZlM2QyZDNlZGIy%250ANWY5MDI3YjY1YzBiYzRmNTRiMjNlYzAzZDoHaWQiJWUwOTk0NzUyNzk1YTk0%250ANDA5NjVmNTQyMjNlMmViMTQ4IgpmbGFzaElDOidBY3Rpb25Db250cm9sbGVy%250AOjpGbGFzaDo6Rmxhc2hIYXNoewAGOgpAdXNlZHsAOhNzaG93X2hlbHBfbGlu%250AazA%253D--e71d494cec5e331a0c75022a30ad32a5ee6c731b
	1320257579.776381	CPRa6u2IqE5UQRRCR	192.150.187.147	51735	199.59.149.200	80	1	GET	api.twitter.com	/receiver.html	http://twitter.com/	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.106 Safari/535.2	0	156	200	OK	-	-	-	(empty)	-	-	-	-	-	FkBulv2apiKmv9gBRg	text/html	__utmz=43838368.1308140498.28.11.utmcsr=nvie.com|utmccn=(referral)|utmcmd=referral|utmcct=/; __utma=43838368.1796737749.1282721850.1308140498.1308206467.29; __utmv=43838368.lang%3A%20en; guest_id=v1%3A13087319415918687; k=10.34.252.113.1320105621891535; original_referer=ZLhHHTiegr8TNr80hgOlP%2FWUU%2FKQ%2BqpM; lang=en; auth_token=cceffe3d2d3edb25f9027b65c0bc4f54b23ec03d; twll=l%3D1320257295; twid=u%3D403579461%7C1Rdt0%2FnmWmtcq3AHIcPk8%2BhHbh0%3D; _twitter_sess=BAh7DzoPY3JlYXRlZF9hdGwrCBDDdmUzAToOcmV0dXJuX3RvIlBodHRwOi8v%250AdHdpdHRlci5jb20vYWNjb3VudC9jb25maXJtX2VtYWlsL1d1cnN0ZmFjaHZl%250Acmt1Zi9DRzdENC01Q0ZDNy0xMzIwMjU6FWluX25ld191c2VyX2Zsb3cwOgd1%250AYTA6DGNzcmZfaWQiJWRlN2RmOGRjMGJjMmRjNGQwNzkzYTRiMTNmNzUyZjI5%250AOgl1c2VyaQRFIg4YOhNwYXNzd29yZF90b2tlbiItY2NlZmZlM2QyZDNlZGIy%250ANWY5MDI3YjY1YzBiYzRmNTRiMjNlYzAzZDoTc2hvd19oZWxwX2xpbmswIgpm%250AbGFzaElDOidBY3Rpb25Db250cm9sbGVyOjpGbGFzaDo6Rmxhc2hIYXNoewAG%250AOgpAdXNlZHsAOgdpZCIlZTA5OTQ3NTI3OTVhOTQ0MDk2NWY1NDIyM2UyZWIx%250ANDg%253D--2d1eb8807f70f8cdf4af1599fa90e683dfb9c9ca
	1320257580.095086	CIgUB437PrImQ8m6G4	192.150.187.147	51742	199.59.149.198	80	1	GET	twitter.com	/	-	Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12	0	58603	200	OK	-	-	-	(empty)	-	-	-	-	-	Fdcilh3f8kcdb846Pe	text/html	__utmz=43838368.1308140498.28.11.utmcsr=nvie.com|utmccn=(referral)|utmcmd=referral|utmcct=/; __utma=43838368.1796737749.1282721850.1308140498.1308206467.29; __utmv=43838368.lang%3A%20en; guest_id=v1%3A13087319415918687; js=1; k=10.34.252.113.1320105621891535; original_referer=padhuUp37zi4XoWogyFqcGgJdw%2BJPXpx; auth_token=cceffe3d2d3edb25f9027b65c0bc4f54b23ec03d; twll=l%3D1320257295; lang=en; twid=u%3D403579461%7C1Rdt0%2FnmWmtcq3AHIcPk8%2BhHbh0%3D; _twitter_sess=BAh7DzoVaW5fbmV3X3VzZXJfZmxvdzA6DnJldHVybl90byJQaHR0cDovL3R3%250AaXR0ZXIuY29tL2FjY291bnQvY29uZmlybV9lbWFpbC9XdXJzdGZhY2h2ZXJr%250AdWYvQ0c3RDQtNUNGQzctMTMyMDI1Og9jcmVhdGVkX2F0bCsIEMN2ZTMBOgl1%250Ac2VyaQRFIg4YOgxjc3JmX2lkIiVkZTdkZjhkYzBiYzJkYzRkMDc5M2E0YjEz%250AZjc1MmYyOToHdWEwOhNwYXNzd29yZF90b2tlbiItY2NlZmZlM2QyZDNlZGIy%250ANWY5MDI3YjY1YzBiYzRmNTRiMjNlYzAzZDoHaWQiJWUwOTk0NzUyNzk1YTk0%250ANDA5NjVmNTQyMjNlMmViMTQ4IgpmbGFzaElDOidBY3Rpb25Db250cm9sbGVy%250AOjpGbGFzaDo6Rmxhc2hIYXNoewAGOgpAdXNlZHsAOhNzaG93X2hlbHBfbGlu%250AazA%253D--e71d494cec5e331a0c75022a30ad32a5ee6c731b
	1320257580.312285	CIgUB437PrImQ8m6G4	192.150.187.147	51742	199.59.149.198	80	2	GET	twitter.com	/favicon.ico	-	Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12	0	1150	200	OK	-	-	-	(empty)	-	-	-	-	-	FJPAu846kQPZ74zxUk	image/x-icon	k=10.35.56.136.1320257543527822; guest_id=v1%3A132025754353173617; _twitter_sess=BAh7DzoPY3JlYXRlZF9hdGwrCBDDdmUzAToOcmV0dXJuX3RvIlBodHRwOi8v%250AdHdpdHRlci5jb20vYWNjb3VudC9jb25maXJtX2VtYWlsL1d1cnN0ZmFjaHZl%250Acmt1Zi9DRzdENC01Q0ZDNy0xMzIwMjU6FWluX25ld191c2VyX2Zsb3cwOhNz%250AaG93X2hlbHBfbGluazA6B3VhMDoMY3NyZl9pZCIlZGU3ZGY4ZGMwYmMyZGM0%250AZDA3OTNhNGIxM2Y3NTJmMjk6CXVzZXJpBEUiDhg6E3Bhc3N3b3JkX3Rva2Vu%250AIi1jY2VmZmUzZDJkM2VkYjI1ZjkwMjdiNjVjMGJjNGY1NGIyM2VjMDNkIgpm%250AbGFzaElDOidBY3Rpb25Db250cm9sbGVyOjpGbGFzaDo6Rmxhc2hIYXNoewAG%250AOgpAdXNlZHsAOgdpZCIlZTA5OTQ3NTI3OTVhOTQ0MDk2NWY1NDIyM2UyZWIx%250ANDg%253D--023c09ca265f7a24e09bb7eb64991540058253e4; original_referer=4bfz%2B%2BmebEkRkMWFCXm%2FCUOsvDoVeFTl; js=1; __utma=43838368.1408749605.1320257546.1320257546.1320257546.1; __utmb=43838368.1.10.1320257546; __utmc=43838368; __utmz=43838368.1320257546.1.1.utmcsr=(direct)|utmccn=(direct)|utmcmd=(none)
	1320257580.617474	CPRa6u2IqE5UQRRCR	192.150.187.147	51735	199.59.149.200	80	2	GET	api.twitter.com	/1/statuses/media_timeline.json?offset=0&count=100&page=0&filter=false&include_entities=true&user_id=403579461	http://api.twitter.com/receiver.html	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.106 Safari/535.2	0	2	200	OK	-	-	-	(empty)	-	-	-	-	-	F3aun44Acnb4IZEss1	text/plain	__utmz=43838368.1308140498.28.11.utmcsr=nvie.com|utmccn=(referral)|utmcmd=referral|utmcct=/; __utma=43838368.1796737749.1282721850.1308140498.1308206467.29; __utmv=43838368.lang%3A%20en; guest_id=v1%3A13087319415918687; k=10.34.252.113.1320105621891535; original_referer=ZLhHHTiegr8TNr80hgOlP%2FWUU%2FKQ%2BqpM; lang=en; auth_token=cceffe3d2d3edb25f9027b65c0bc4f54b23ec03d; twll=l%3D1320257295; twid=u%3D403579461%7C1Rdt0%2FnmWmtcq3AHIcPk8%2BhHbh0%3D; _twitter_sess=BAh7DzoPY3JlYXRlZF9hdGwrCBDDdmUzAToOcmV0dXJuX3RvIlBodHRwOi8v%250AdHdpdHRlci5jb20vYWNjb3VudC9jb25maXJtX2VtYWlsL1d1cnN0ZmFjaHZl%250Acmt1Zi9DRzdENC01Q0ZDNy0xMzIwMjU6FWluX25ld191c2VyX2Zsb3cwOgd1%250AYTA6DGNzcmZfaWQiJWRlN2RmOGRjMGJjMmRjNGQwNzkzYTRiMTNmNzUyZjI5%250AOgl1c2VyaQRFIg4YOhNwYXNzd29yZF90b2tlbiItY2NlZmZlM2QyZDNlZGIy%250ANWY5MDI3YjY1YzBiYzRmNTRiMjNlYzAzZDoTc2hvd19oZWxwX2xpbmswIgpm%250AbGFzaElDOidBY3Rpb25Db250cm9sbGVyOjpGbGFzaDo6Rmxhc2hIYXNoewAG%250AOgpAdXNlZHsAOgdpZCIlZTA5OTQ3NTI3OTVhOTQ0MDk2NWY1NDIyM2UyZWIx%250ANDg%253D--2d1eb8807f70f8cdf4af1599fa90e683dfb9c9ca
	1320257580.633328	CkhRlIrrZuCUbV7Ff	192.150.187.147	51736	199.59.149.200	80	1	GET	api.twitter.com	/1/friendships/show.json?source_id=403579461&target_screen_name=browurstfach	http://api.twitter.com/receiver.html	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.106 Safari/535.2	0	369	200	OK	-	-	-	(empty)	-	-	-	-	-	FlM0Ch4UfCI52Pik9g	text/plain	__utmz=43838368.1308140498.28.11.utmcsr=nvie.com|utmccn=(referral)|utmcmd=referral|utmcct=/; __utma=43838368.1796737749.1282721850.1308140498.1308206467.29; __utmv=43838368.lang%3A%20en; guest_id=v1%3A13087319415918687; k=10.34.252.113.1320105621891535; original_referer=ZLhHHTiegr8TNr80hgOlP%2FWUU%2FKQ%2BqpM; lang=en; auth_token=cceffe3d2d3edb25f9027b65c0bc4f54b23ec03d; twll=l%3D1320257295; twid=u%3D403579461%7C1Rdt0%2FnmWmtcq3AHIcPk8%2BhHbh0%3D; _twitter_sess=BAh7DzoPY3JlYXRlZF9hdGwrCBDDdmUzAToOcmV0dXJuX3RvIlBodHRwOi8v%250AdHdpdHRlci5jb20vYWNjb3VudC9jb25maXJtX2VtYWlsL1d1cnN0ZmFjaHZl%250Acmt1Zi9DRzdENC01Q0ZDNy0xMzIwMjU6FWluX25ld191c2VyX2Zsb3cwOgd1%250AYTA6DGNzcmZfaWQiJWRlN2RmOGRjMGJjMmRjNGQwNzkzYTRiMTNmNzUyZjI5%250AOgl1c2VyaQRFIg4YOhNwYXNzd29yZF90b2tlbiItY2NlZmZlM2QyZDNlZGIy%250ANWY5MDI3YjY1YzBiYzRmNTRiMjNlYzAzZDoTc2hvd19oZWxwX2xpbmswIgpm%250AbGFzaElDOidBY3Rpb25Db250cm9sbGVyOjpGbGFzaDo6Rmxhc2hIYXNoewAG%250AOgpAdXNlZHsAOgdpZCIlZTA5OTQ3NTI3OTVhOTQ0MDk2NWY1NDIyM2UyZWIx%250ANDg%253D--2d1eb8807f70f8cdf4af1599fa90e683dfb9c9ca
	1320257580.732518	CkhRlIrrZuCUbV7Ff	192.150.187.147	51736	199.59.149.200	80	2	GET	api.twitter.com	/1/statuses/user_timeline.json?include_entities=1&include_available_features=1&contributor_details=true&pc=false&include_rts=true&user_id=403579461	http://api.twitter.com/receiver.html	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.106 Safari/535.2	0	4974	200	OK	-	-	-	(empty)	-	-	-	-	-	FdnQFO2zbignAGYqb6	text/plain	__utmz=43838368.1308140498.28.11.utmcsr=nvie.com|utmccn=(referral)|utmcmd=referral|utmcct=/; __utma=43838368.1796737749.1282721850.1308140498.1308206467.29; __utmv=43838368.lang%3A%20en; guest_id=v1%3A13087319415918687; k=10.34.252.113.1320105621891535; original_referer=ZLhHHTiegr8TNr80hgOlP%2FWUU%2FKQ%2BqpM; lang=en; auth_token=cceffe3d2d3edb25f9027b65c0bc4f54b23ec03d; twll=l%3D1320257295; twid=u%3D403579461%7C1Rdt0%2FnmWmtcq3AHIcPk8%2BhHbh0%3D; _twitter_sess=BAh7DzoVaW5fbmV3X3VzZXJfZmxvdzA6DnJldHVybl90byJQaHR0cDovL3R3%250AaXR0ZXIuY29tL2FjY291bnQvY29uZmlybV9lbWFpbC9XdXJzdGZhY2h2ZXJr%250AdWYvQ0c3RDQtNUNGQzctMTMyMDI1Og9jcmVhdGVkX2F0bCsIEMN2ZTMBOgl1%250Ac2VyaQRFIg4YOgxjc3JmX2lkIiVkZTdkZjhkYzBiYzJkYzRkMDc5M2E0YjEz%250AZjc1MmYyOToHdWEwOhNwYXNzd29yZF90b2tlbiItY2NlZmZlM2QyZDNlZGIy%250ANWY5MDI3YjY1YzBiYzRmNTRiMjNlYzAzZDoHaWQiJWUwOTk0NzUyNzk1YTk0%250ANDA5NjVmNTQyMjNlMmViMTQ4IgpmbGFzaElDOidBY3Rpb25Db250cm9sbGVy%250AOjpGbGFzaDo6Rmxhc2hIYXNoewAGOgpAdXNlZHsAOhNzaG93X2hlbHBfbGlu%250AazA%253D--e71d494cec5e331a0c75022a30ad32a5ee6c731b
	1320257582.613059	CucuIk2HsJymJ7RzL1	192.150.187.147	51731	199.59.149.230	80	2	POST	twitter.com	/scribe	http://twitter.com/	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.106 Safari/535.2	1365	1	200	OK	-	-	-	(empty)	-	-	-	FIU3Im1kOpOompYYJl	text/plain	Fgt6X72Y2WaVaDAyVh	application/octet-stream	__utmz=43838368.1308140498.28.11.utmcsr=nvie.com|utmccn=(referral)|utmcmd=referral|utmcct=/; __utma=43838368.1796737749.1282721850.1308140498.1308206467.29; __utmv=43838368.lang%3A%20en; guest_id=v1%3A13087319415918687; js=1; k=10.34.252.113.1320105621891535; original_referer=padhuUp37zi4XoWogyFqcGgJdw%2BJPXpx; auth_token=cceffe3d2d3edb25f9027b65c0bc4f54b23ec03d; twll=l%3D1320257295; lang=en; twid=u%3D403579461%7C1Rdt0%2FnmWmtcq3AHIcPk8%2BhHbh0%3D; _twitter_sess=BAh7DzoPY3JlYXRlZF9hdGwrCBDDdmUzAToOcmV0dXJuX3RvIlBodHRwOi8v%250AdHdpdHRlci5jb20vYWNjb3VudC9jb25maXJtX2VtYWlsL1d1cnN0ZmFjaHZl%250Acmt1Zi9DRzdENC01Q0ZDNy0xMzIwMjU6FWluX25ld191c2VyX2Zsb3cwOgd1%250AYTA6DGNzcmZfaWQiJWRlN2RmOGRjMGJjMmRjNGQwNzkzYTRiMTNmNzUyZjI5%250AOgl1c2VyaQRFIg4YOhNwYXNzd29yZF90b2tlbiItY2NlZmZlM2QyZDNlZGIy%250ANWY5MDI3YjY1YzBiYzRmNTRiMjNlYzAzZDoTc2hvd19oZWxwX2xpbmswIgpm%250AbGFzaElDOidBY3Rpb25Db250cm9sbGVyOjpGbGFzaDo6Rmxhc2hIYXNoewAG%250AOgpAdXNlZHsAOgdpZCIlZTA5OTQ3NTI3OTVhOTQ0MDk2NWY1NDIyM2UyZWIx%250ANDg%253D--2d1eb8807f70f8cdf4af1599fa90e683dfb9c9ca
	1320257588.192149	CIgUB437PrImQ8m6G4	192.150.187.147	51742	199.59.149.198	80	3	GET	twitter.com	/	-	Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12	0	58625	200	OK	-	-	-	(empty)	-	-	-	-	-	F0C7653otQvQ7tiQY5	text/html	__utmz=43838368.1308140498.28.11.utmcsr=nvie.com|utmccn=(referral)|utmcmd=referral|utmcct=/; __utma=43838368.1796737749.1282721850.1308140498.1308206467.29; __utmv=43838368.lang%3A%20en; guest_id=v1%3A13087319415918687; js=1; k=10.34.252.113.1320105621891535; original_referer=padhuUp37zi4XoWogyFqcGgJdw%2BJPXpx; auth_token=cceffe3d2d3edb25f9027b65c0bc4f54b23ec03d; twll=l%3D1320257295; lang=en; twid=u%3D403579461%7C1Rdt0%2FnmWmtcq3AHIcPk8%2BhHbh0%3D; _twitter_sess=BAh7DzoVaW5fbmV3X3VzZXJfZmxvdzA6DnJldHVybl90byJQaHR0cDovL3R3%250AaXR0ZXIuY29tL2FjY291bnQvY29uZmlybV9lbWFpbC9XdXJzdGZhY2h2ZXJr%250AdWYvQ0c3RDQtNUNGQzctMTMyMDI1Og9jcmVhdGVkX2F0bCsIEMN2ZTMBOgl1%250Ac2VyaQRFIg4YOgxjc3JmX2lkIiVkZTdkZjhkYzBiYzJkYzRkMDc5M2E0YjEz%250AZjc1MmYyOToHdWEwOhNwYXNzd29yZF90b2tlbiItY2NlZmZlM2QyZDNlZGIy%250ANWY5MDI3YjY1YzBiYzRmNTRiMjNlYzAzZDoHaWQiJWUwOTk0NzUyNzk1YTk0%250ANDA5NjVmNTQyMjNlMmViMTQ4IgpmbGFzaElDOidBY3Rpb25Db250cm9sbGVy%250AOjpGbGFzaDo6Rmxhc2hIYXNoewAGOgpAdXNlZHsAOhNzaG93X2hlbHBfbGlu%250AazA%253D--e71d494cec5e331a0c75022a30ad32a5ee6c731b
	1320257590.217149	CIgUB437PrImQ8m6G4	192.150.187.147	51742	199.59.149.198	80	4	GET	twitter.com	/images/spinner.gif	http://twitter.com/	Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12	0	457	200	OK	-	-	-	(empty)	-	-	-	-	-	FELl5RJ95raNOfpz5	image/gif	__utmz=43838368.1308140498.28.11.utmcsr=nvie.com|utmccn=(referral)|utmcmd=referral|utmcct=/; __utma=43838368.1796737749.1282721850.1308140498.1308206467.29; __utmv=43838368.lang%3A%20en; guest_id=v1%3A13087319415918687; js=1; k=10.34.252.113.1320105621891535; original_referer=padhuUp37zi4XoWogyFqcGgJdw%2BJPXpx; auth_token=cceffe3d2d3edb25f9027b65c0bc4f54b23ec03d; twll=l%3D1320257295; lang=en; twid=u%3D403579461%7C1Rdt0%2FnmWmtcq3AHIcPk8%2BhHbh0%3D; _twitter_sess=BAh7DzoTc2hvd19oZWxwX2xpbmswOg9jcmVhdGVkX2F0bCsIEMN2ZTMBOg5y%250AZXR1cm5fdG8iUGh0dHA6Ly90d2l0dGVyLmNvbS9hY2NvdW50L2NvbmZpcm1f%250AZW1haWwvV3Vyc3RmYWNodmVya3VmL0NHN0Q0LTVDRkM3LTEzMjAyNToVaW5f%250AbmV3X3VzZXJfZmxvdzA6B3VhMDoMY3NyZl9pZCIlZGU3ZGY4ZGMwYmMyZGM0%250AZDA3OTNhNGIxM2Y3NTJmMjk6CXVzZXJpBEUiDhg6E3Bhc3N3b3JkX3Rva2Vu%250AIi1jY2VmZmUzZDJkM2VkYjI1ZjkwMjdiNjVjMGJjNGY1NGIyM2VjMDNkIgpm%250AbGFzaElDOidBY3Rpb25Db250cm9sbGVyOjpGbGFzaDo6Rmxhc2hIYXNoewAG%250AOgpAdXNlZHsAOgdpZCIlZTA5OTQ3NTI3OTVhOTQ0MDk2NWY1NDIyM2UyZWIx%250ANDg%253D--e759ee3598dbf31c78e7042b2979869ce59af7e5
	1320257590.268932	CIgUB437PrImQ8m6G4	192.150.187.147	51742	199.59.149.198	80	5	GET	twitter.com	/promos/random_json_promo?promo_type=&limit=1	http://twitter.com/	Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12	0	505	200	OK	-	-	-	(empty)	-	-	-	-	-	F2ui9y1RKcxM20cUle	text/plain	__utmz=43838368.1308140498.28.11.utmcsr=nvie.com|utmccn=(referral)|utmcmd=referral|utmcct=/; __utma=43838368.1796737749.1282721850.1308140498.1308206467.29; __utmv=43838368.lang%3A%20en; guest_id=v1%3A13087319415918687; js=1; k=10.34.252.113.1320105621891535; original_referer=padhuUp37zi4XoWogyFqcGgJdw%2BJPXpx; auth_token=cceffe3d2d3edb25f9027b65c0bc4f54b23ec03d; twll=l%3D1320257295; lang=en; twid=u%3D403579461%7C1Rdt0%2FnmWmtcq3AHIcPk8%2BhHbh0%3D; _twitter_sess=BAh7DzoTc2hvd19oZWxwX2xpbmswOg9jcmVhdGVkX2F0bCsIEMN2ZTMBOg5y%250AZXR1cm5fdG8iUGh0dHA6Ly90d2l0dGVyLmNvbS9hY2NvdW50L2NvbmZpcm1f%250AZW1haWwvV3Vyc3RmYWNodmVya3VmL0NHN0Q0LTVDRkM3LTEzMjAyNToVaW5f%250AbmV3X3VzZXJfZmxvdzA6B3VhMDoMY3NyZl9pZCIlZGU3ZGY4ZGMwYmMyZGM0%250AZDA3OTNhNGIxM2Y3NTJmMjk6CXVzZXJpBEUiDhg6E3Bhc3N3b3JkX3Rva2Vu%250AIi1jY2VmZmUzZDJkM2VkYjI1ZjkwMjdiNjVjMGJjNGY1NGIyM2VjMDNkIgpm%250AbGFzaElDOidBY3Rpb25Db250cm9sbGVyOjpGbGFzaDo6Rmxhc2hIYXNoewAG%250AOgpAdXNlZHsAOgdpZCIlZTA5OTQ3NTI3OTVhOTQ0MDk2NWY1NDIyM2UyZWIx%250ANDg%253D--e759ee3598dbf31c78e7042b2979869ce59af7e5
	1320257590.308726	C29z7G4daJC3Hbjok9	192.150.187.147	51749	199.59.149.198	80	1	GET	twitter.com	/find_sources/contacts/services.json	http://twitter.com/	Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12	0	1121	200	OK	-	-	-	(empty)	-	-	-	-	-	F1UJBJ3r2YMpSWdzqf	text/plain	__utmz=43838368.1308140498.28.11.utmcsr=nvie.com|utmccn=(referral)|utmcmd=referral|utmcct=/; __utma=43838368.1796737749.1282721850.1308140498.1308206467.29; __utmv=43838368.lang%3A%20en; guest_id=v1%3A13087319415918687; js=1; k=10.34.252.113.1320105621891535; original_referer=padhuUp37zi4XoWogyFqcGgJdw%2BJPXpx; auth_token=cceffe3d2d3edb25f9027b65c0bc4f54b23ec03d; twll=l%3D1320257295; lang=en; twid=u%3D403579461%7C1Rdt0%2FnmWmtcq3AHIcPk8%2BhHbh0%3D; _twitter_sess=BAh7DzoTc2hvd19oZWxwX2xpbmswOg9jcmVhdGVkX2F0bCsIEMN2ZTMBOg5y%250AZXR1cm5fdG8iUGh0dHA6Ly90d2l0dGVyLmNvbS9hY2NvdW50L2NvbmZpcm1f%250AZW1haWwvV3Vyc3RmYWNodmVya3VmL0NHN0Q0LTVDRkM3LTEzMjAyNToVaW5f%250AbmV3X3VzZXJfZmxvdzA6B3VhMDoMY3NyZl9pZCIlZGU3ZGY4ZGMwYmMyZGM0%250AZDA3OTNhNGIxM2Y3NTJmMjk6CXVzZXJpBEUiDhg6E3Bhc3N3b3JkX3Rva2Vu%250AIi1jY2VmZmUzZDJkM2VkYjI1ZjkwMjdiNjVjMGJjNGY1NGIyM2VjMDNkIgpm%250AbGFzaElDOidBY3Rpb25Db250cm9sbGVyOjpGbGFzaDo6Rmxhc2hIYXNoewAG%250AOgpAdXNlZHsAOgdpZCIlZTA5OTQ3NTI3OTVhOTQ0MDk2NWY1NDIyM2UyZWIx%250ANDg%253D--e759ee3598dbf31c78e7042b2979869ce59af7e5
	1320257590.307644	Cu5Zyc1yjOGSXvWoVh	192.150.187.147	51750	199.59.149.200	80	1	GET	api.twitter.com	/1/users/recommendations.json?limit=3&display_location=wtf-component&pc=true&connections=true	http://api.twitter.com/receiver.html	Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12	0	5713	200	OK	-	-	-	(empty)	-	-	-	-	-	F9ahVF1alM8f5dYgdi	text/plain	__utmz=43838368.1308140498.28.11.utmcsr=nvie.com|utmccn=(referral)|utmcmd=referral|utmcct=/; __utma=43838368.1796737749.1282721850.1308140498.1308206467.29; __utmv=43838368.lang%3A%20en; guest_id=v1%3A13087319415918687; js=1; k=10.34.252.113.1320105621891535; original_referer=padhuUp37zi4XoWogyFqcGgJdw%2BJPXpx; auth_token=cceffe3d2d3edb25f9027b65c0bc4f54b23ec03d; twll=l%3D1320257295; lang=en; twid=u%3D403579461%7C1Rdt0%2FnmWmtcq3AHIcPk8%2BhHbh0%3D; _twitter_sess=BAh7DzoTc2hvd19oZWxwX2xpbmswOg9jcmVhdGVkX2F0bCsIEMN2ZTMBOg5y%250AZXR1cm5fdG8iUGh0dHA6Ly90d2l0dGVyLmNvbS9hY2NvdW50L2NvbmZpcm1f%250AZW1haWwvV3Vyc3RmYWNodmVya3VmL0NHN0Q0LTVDRkM3LTEzMjAyNToVaW5f%250AbmV3X3VzZXJfZmxvdzA6B3VhMDoMY3NyZl9pZCIlZGU3ZGY4ZGMwYmMyZGM0%250AZDA3OTNhNGIxM2Y3NTJmMjk6CXVzZXJpBEUiDhg6E3Bhc3N3b3JkX3Rva2Vu%250AIi1jY2VmZmUzZDJkM2VkYjI1ZjkwMjdiNjVjMGJjNGY1NGIyM2VjMDNkIgpm%250AbGFzaElDOidBY3Rpb25Db250cm9sbGVyOjpGbGFzaDo6Rmxhc2hIYXNoewAG%250AOgpAdXNlZHsAOgdpZCIlZTA5OTQ3NTI3OTVhOTQ0MDk2NWY1NDIyM2UyZWIx%250ANDg%253D--e759ee3598dbf31c78e7042b2979869ce59af7e5
	1320257590.289573	Cg8P5f1TXpD8XeRC4i	192.150.187.147	51748	199.59.149.200	80	1	GET	api.twitter.com	/1/trends/available.json?lang=en	http://api.twitter.com/receiver.html	Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12	0	21317	200	OK	-	-	-	(empty)	-	-	-	-	-	F6UYi6h7AMsvWrgR	text/plain	__utmz=43838368.1308140498.28.11.utmcsr=nvie.com|utmccn=(referral)|utmcmd=referral|utmcct=/; __utma=43838368.1796737749.1282721850.1308140498.1308206467.29; __utmv=43838368.lang%3A%20en; guest_id=v1%3A13087319415918687; js=1; k=10.34.252.113.1320105621891535; original_referer=padhuUp37zi4XoWogyFqcGgJdw%2BJPXpx; auth_token=cceffe3d2d3edb25f9027b65c0bc4f54b23ec03d; twll=l%3D1320257295; lang=en; twid=u%3D403579461%7C1Rdt0%2FnmWmtcq3AHIcPk8%2BhHbh0%3D; _twitter_sess=BAh7DzoTc2hvd19oZWxwX2xpbmswOg9jcmVhdGVkX2F0bCsIEMN2ZTMBOg5y%250AZXR1cm5fdG8iUGh0dHA6Ly90d2l0dGVyLmNvbS9hY2NvdW50L2NvbmZpcm1f%250AZW1haWwvV3Vyc3RmYWNodmVya3VmL0NHN0Q0LTVDRkM3LTEzMjAyNToVaW5f%250AbmV3X3VzZXJfZmxvdzA6B3VhMDoMY3NyZl9pZCIlZGU3ZGY4ZGMwYmMyZGM0%250AZDA3OTNhNGIxM2Y3NTJmMjk6CXVzZXJpBEUiDhg6E3Bhc3N3b3JkX3Rva2Vu%250AIi1jY2VmZmUzZDJkM2VkYjI1ZjkwMjdiNjVjMGJjNGY1NGIyM2VjMDNkIgpm%250AbGFzaElDOidBY3Rpb25Db250cm9sbGVyOjpGbGFzaDo6Rmxhc2hIYXNoewAG%250AOgpAdXNlZHsAOgdpZCIlZTA5OTQ3NTI3OTVhOTQ0MDk2NWY1NDIyM2UyZWIx%250ANDg%253D--e759ee3598dbf31c78e7042b2979869ce59af7e5
	1320257590.601578	CfAm1I1IJ8D1HtsTvh	192.150.187.147	51751	184.169.75.33	80	1	GET	a1.twimg.com	/profile_images/1186165568/paul_normal.png	http://twitter.com/	Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12	0	6319	200	OK	-	-	-	(empty)	-	-	-	-	-	FkN0023NOSZf7u7b15	image/png	-
	1320257590.605079	CzeX3K1XkEipxJA9Ih	192.150.187.147	51753	198.189.255.224	80	1	GET	a3.twimg.com	/a/1320212170/phoenix/img/sprite-icons.png	http://a3.twimg.com/a/1320212170/phoenix/css/phoenix_more.bundle.css	Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12	0	19149	200	OK	-	-	-	(empty)	-	-	-	-	-	Fkr2nA48i7Spz6toy1	image/png	-
	1320257590.780826	Cu5Zyc1yjOGSXvWoVh	192.150.187.147	51750	199.59.149.200	80	2	GET	api.twitter.com	/1/trends/1.json?pc=true&personalized=false	http://api.twitter.com/receiver.html	Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12	0	1718	200	OK	-	-	-	(empty)	-	-	-	-	-	FisHtl2X7rWpF3sQO9	text/plain	__utmz=43838368.1308140498.28.11.utmcsr=nvie.com|utmccn=(referral)|utmcmd=referral|utmcct=/; __utma=43838368.1796737749.1282721850.1308206467.1320257591.30; __utmv=43838368.lang%3A%20en; guest_id=v1%3A13087319415918687; js=1; k=10.34.252.113.1320105621891535; original_referer=padhuUp37zi4XoWogyFqcGgJdw%2BJPXpx; auth_token=cceffe3d2d3edb25f9027b65c0bc4f54b23ec03d; twll=l%3D1320257295; lang=en; twid=u%3D403579461%7C1Rdt0%2FnmWmtcq3AHIcPk8%2BhHbh0%3D; _twitter_sess=BAh7DzoVaW5fbmV3X3VzZXJfZmxvdzA6DnJldHVybl90byJQaHR0cDovL3R3%250AaXR0ZXIuY29tL2FjY291bnQvY29uZmlybV9lbWFpbC9XdXJzdGZhY2h2ZXJr%250AdWYvQ0c3RDQtNUNGQzctMTMyMDI1Og9jcmVhdGVkX2F0bCsIEMN2ZTMBOgl1%250Ac2VyaQRFIg4YOgxjc3JmX2lkIiVkZTdkZjhkYzBiYzJkYzRkMDc5M2E0YjEz%250AZjc1MmYyOToHdWEwOhNwYXNzd29yZF90b2tlbiItY2NlZmZlM2QyZDNlZGIy%250ANWY5MDI3YjY1YzBiYzRmNTRiMjNlYzAzZDoTc2hvd19oZWxwX2xpbmswOgdp%250AZCIlZTA5OTQ3NTI3OTVhOTQ0MDk2NWY1NDIyM2UyZWIxNDgiCmZsYXNoSUM6%250AJ0FjdGlvbkNvbnRyb2xsZXI6OkZsYXNoOjpGbGFzaEhhc2h7AAY6CkB1c2Vk%250AewA%253D--4ac3417bc2e5682925b12b9f596918726fe96b64; __utmb=43838368.1.10.1320257591; __utmc=43838368
	1320257590.601602	ClHUt74kPprDqGlMN9	192.150.187.147	51752	184.169.75.33	80	1	GET	a1.twimg.com	/profile_images/812305325/n1052539666_30051083_3817_normal.jpg	http://twitter.com/	Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12	0	969	200	OK	-	-	-	(empty)	-	-	-	-	-	FuBeHZ2YNU2N8u0n13	image/jpeg	-
	1320257595.855957	C29z7G4daJC3Hbjok9	192.150.187.147	51749	199.59.149.198	80	2	POST	twitter.com	/scribe	http://twitter.com/	Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12	3581	1	200	OK	-	-	-	(empty)	-	-	-	FOhBwU1fqZ15gDqG63	text/plain	F8UpvTJcPpN6oVNIa	application/octet-stream	__utmz=43838368.1308140498.28.11.utmcsr=nvie.com|utmccn=(referral)|utmcmd=referral|utmcct=/; __utma=43838368.1796737749.1282721850.1308206467.1320257591.30; __utmv=43838368.lang%3A%20en; guest_id=v1%3A13087319415918687; js=1; k=10.34.252.113.1320105621891535; original_referer=padhuUp37zi4XoWogyFqcGgJdw%2BJPXpx; auth_token=cceffe3d2d3edb25f9027b65c0bc4f54b23ec03d; twll=l%3D1320257295; lang=en; twid=u%3D403579461%7C1Rdt0%2FnmWmtcq3AHIcPk8%2BhHbh0%3D; _twitter_sess=BAh7DzoPY3JlYXRlZF9hdGwrCBDDdmUzAToOcmV0dXJuX3RvIlBodHRwOi8v%250AdHdpdHRlci5jb20vYWNjb3VudC9jb25maXJtX2VtYWlsL1d1cnN0ZmFjaHZl%250Acmt1Zi9DRzdENC01Q0ZDNy0xMzIwMjU6FWluX25ld191c2VyX2Zsb3cwOhNz%250AaG93X2hlbHBfbGluazA6B3VhMDoMY3NyZl9pZCIlZGU3ZGY4ZGMwYmMyZGM0%250AZDA3OTNhNGIxM2Y3NTJmMjk6CXVzZXJpBEUiDhg6E3Bhc3N3b3JkX3Rva2Vu%250AIi1jY2VmZmUzZDJkM2VkYjI1ZjkwMjdiNjVjMGJjNGY1NGIyM2VjMDNkIgpm%250AbGFzaElDOidBY3Rpb25Db250cm9sbGVyOjpGbGFzaDo6Rmxhc2hIYXNoewAG%250AOgpAdXNlZHsAOgdpZCIlZTA5OTQ3NTI3OTVhOTQ0MDk2NWY1NDIyM2UyZWIx%250ANDg%253D--023c09ca265f7a24e09bb7eb64991540058253e4; __utmb=43838368.1.10.1320257591; __utmc=43838368
	1320257600.451006	CfAm1I1IJ8D1HtsTvh	192.150.187.147	51751	184.169.75.33	80	2	GET	a1.twimg.com	/a/1320212170/images/default_profile_add_photo.png	http://twitter.com/	Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12	0	4031	200	OK	-	-	-	(empty)	-	-	-	-	-	FJaBeljRRB4Bciax2	image/png	-
	1320257600.481436	Cu5Zyc1yjOGSXvWoVh	192.150.187.147	51750	199.59.149.200	80	3	GET	api.twitter.com	/1/statuses/media_timeline.json?offset=0&count=100&page=0&filter=false&include_entities=true&user_id=403579461	http://api.twitter.com/receiver.html	Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12	0	2	200	OK	-	-	-	(empty)	-	-	-	-	-	F43myr2GsPP4KsvRO3	text/plain	__utmz=43838368.1308140498.28.11.utmcsr=nvie.com|utmccn=(referral)|utmcmd=referral|utmcct=/; __utma=43838368.1796737749.1282721850.1308206467.1320257591.30; __utmv=43838368.lang%3A%20en; guest_id=v1%3A13087319415918687; js=1; k=10.34.252.113.1320105621891535; original_referer=padhuUp37zi4XoWogyFqcGgJdw%2BJPXpx; auth_token=cceffe3d2d3edb25f9027b65c0bc4f54b23ec03d; twll=l%3D1320257295; lang=en; twid=u%3D403579461%7C1Rdt0%2FnmWmtcq3AHIcPk8%2BhHbh0%3D; _twitter_sess=BAh7DzoHdWEwOhNzaG93X2hlbHBfbGluazA6DGNzcmZfaWQiJWRlN2RmOGRj%250AMGJjMmRjNGQwNzkzYTRiMTNmNzUyZjI5OhNwYXNzd29yZF90b2tlbiItY2Nl%250AZmZlM2QyZDNlZGIyNWY5MDI3YjY1YzBiYzRmNTRiMjNlYzAzZDoPY3JlYXRl%250AZF9hdGwrCBDDdmUzAToOcmV0dXJuX3RvIlBodHRwOi8vdHdpdHRlci5jb20v%250AYWNjb3VudC9jb25maXJtX2VtYWlsL1d1cnN0ZmFjaHZlcmt1Zi9DRzdENC01%250AQ0ZDNy0xMzIwMjU6B2lkIiVlMDk5NDc1Mjc5NWE5NDQwOTY1ZjU0MjIzZTJl%250AYjE0OCIKZmxhc2hJQzonQWN0aW9uQ29udHJvbGxlcjo6Rmxhc2g6OkZsYXNo%250ASGFzaHsABjoKQHVzZWR7ADoJdXNlcmkERSIOGDoVaW5fbmV3X3VzZXJfZmxv%250AdzA%253D--c5358a367b4b71a46bbb6e08881ba0ba9b6136c8; __utmb=43838368.2.10.1320257591; __utmc=43838368
	1320257600.531341	Cnv4A81yefTH2hW43f	192.150.187.147	51754	199.59.149.200	80	1	GET	api.twitter.com	/1/friendships/show.json?source_id=403579461&target_screen_name=browurstfach	http://api.twitter.com/receiver.html	Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12	0	369	200	OK	-	-	-	(empty)	-	-	-	-	-	F8Munx1Wl6JA1PM1kd	text/plain	__utmz=43838368.1308140498.28.11.utmcsr=nvie.com|utmccn=(referral)|utmcmd=referral|utmcct=/; __utma=43838368.1796737749.1282721850.1308206467.1320257591.30; __utmv=43838368.lang%3A%20en; guest_id=v1%3A13087319415918687; js=1; k=10.34.252.113.1320105621891535; original_referer=padhuUp37zi4XoWogyFqcGgJdw%2BJPXpx; auth_token=cceffe3d2d3edb25f9027b65c0bc4f54b23ec03d; twll=l%3D1320257295; lang=en; twid=u%3D403579461%7C1Rdt0%2FnmWmtcq3AHIcPk8%2BhHbh0%3D; _twitter_sess=BAh7DzoHdWEwOhNzaG93X2hlbHBfbGluazA6DGNzcmZfaWQiJWRlN2RmOGRj%250AMGJjMmRjNGQwNzkzYTRiMTNmNzUyZjI5OhNwYXNzd29yZF90b2tlbiItY2Nl%250AZmZlM2QyZDNlZGIyNWY5MDI3YjY1YzBiYzRmNTRiMjNlYzAzZDoPY3JlYXRl%250AZF9hdGwrCBDDdmUzAToOcmV0dXJuX3RvIlBodHRwOi8vdHdpdHRlci5jb20v%250AYWNjb3VudC9jb25maXJtX2VtYWlsL1d1cnN0ZmFjaHZlcmt1Zi9DRzdENC01%250AQ0ZDNy0xMzIwMjU6B2lkIiVlMDk5NDc1Mjc5NWE5NDQwOTY1ZjU0MjIzZTJl%250AYjE0OCIKZmxhc2hJQzonQWN0aW9uQ29udHJvbGxlcjo6Rmxhc2g6OkZsYXNo%250ASGFzaHsABjoKQHVzZWR7ADoJdXNlcmkERSIOGDoVaW5fbmV3X3VzZXJfZmxv%250AdzA%253D--c5358a367b4b71a46bbb6e08881ba0ba9b6136c8; __utmb=43838368.2.10.1320257591; __utmc=43838368
	1320257600.615428	CtoeA615jhs6drG1Re	192.150.187.147	51755	199.59.149.200	80	1	GET	api.twitter.com	/1/statuses/user_timeline.json?include_entities=1&include_available_features=1&contributor_details=true&pc=false&include_rts=true&user_id=403579461	http://api.twitter.com/receiver.html	Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12	0	4974	200	OK	-	-	-	(empty)	-	-	-	-	-	FyBEjKHZ7oTm3dVR3	text/plain	__utmz=43838368.1308140498.28.11.utmcsr=nvie.com|utmccn=(referral)|utmcmd=referral|utmcct=/; __utma=43838368.1796737749.1282721850.1308206467.1320257591.30; __utmv=43838368.lang%3A%20en; guest_id=v1%3A13087319415918687; js=1; k=10.34.252.113.1320105621891535; original_referer=padhuUp37zi4XoWogyFqcGgJdw%2BJPXpx; auth_token=cceffe3d2d3edb25f9027b65c0bc4f54b23ec03d; twll=l%3D1320257295; lang=en; twid=u%3D403579461%7C1Rdt0%2FnmWmtcq3AHIcPk8%2BhHbh0%3D; _twitter_sess=BAh7DzoHdWEwOhNzaG93X2hlbHBfbGluazA6DGNzcmZfaWQiJWRlN2RmOGRj%250AMGJjMmRjNGQwNzkzYTRiMTNmNzUyZjI5OhNwYXNzd29yZF90b2tlbiItY2Nl%250AZmZlM2QyZDNlZGIyNWY5MDI3YjY1YzBiYzRmNTRiMjNlYzAzZDoPY3JlYXRl%250AZF9hdGwrCBDDdmUzAToOcmV0dXJuX3RvIlBodHRwOi8vdHdpdHRlci5jb20v%250AYWNjb3VudC9jb25maXJtX2VtYWlsL1d1cnN0ZmFjaHZlcmt1Zi9DRzdENC01%250AQ0ZDNy0xMzIwMjU6B2lkIiVlMDk5NDc1Mjc5NWE5NDQwOTY1ZjU0MjIzZTJl%250AYjE0OCIKZmxhc2hJQzonQWN0aW9uQ29udHJvbGxlcjo6Rmxhc2g6OkZsYXNo%250ASGFzaHsABjoKQHVzZWR7ADoJdXNlcmkERSIOGDoVaW5fbmV3X3VzZXJfZmxv%250AdzA%253D--c5358a367b4b71a46bbb6e08881ba0ba9b6136c8; __utmb=43838368.2.10.1320257591; __utmc=43838368
	1320257600.736737	C29z7G4daJC3Hbjok9	192.150.187.147	51749	199.59.149.198	80	3	GET	twitter.com	/phoenix/img/tiny-timeline-bird.png	http://twitter.com/	Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12	0	491	200	OK	-	-	-	(empty)	-	-	-	-	-	F2uLtI2MMItGsI599c	image/png	__utmz=43838368.1308140498.28.11.utmcsr=nvie.com|utmccn=(referral)|utmcmd=referral|utmcct=/; __utma=43838368.1796737749.1282721850.1308206467.1320257591.30; __utmv=43838368.lang%3A%20en; guest_id=v1%3A13087319415918687; js=1; k=10.34.252.113.1320105621891535; original_referer=padhuUp37zi4XoWogyFqcGgJdw%2BJPXpx; auth_token=cceffe3d2d3edb25f9027b65c0bc4f54b23ec03d; twll=l%3D1320257295; lang=en; twid=u%3D403579461%7C1Rdt0%2FnmWmtcq3AHIcPk8%2BhHbh0%3D; _twitter_sess=BAh7DzoVaW5fbmV3X3VzZXJfZmxvdzA6DnJldHVybl90byJQaHR0cDovL3R3%250AaXR0ZXIuY29tL2FjY291bnQvY29uZmlybV9lbWFpbC9XdXJzdGZhY2h2ZXJr%250AdWYvQ0c3RDQtNUNGQzctMTMyMDI1Og9jcmVhdGVkX2F0bCsIEMN2ZTMBOhNz%250AaG93X2hlbHBfbGluazA6CXVzZXJpBEUiDhg6DGNzcmZfaWQiJWRlN2RmOGRj%250AMGJjMmRjNGQwNzkzYTRiMTNmNzUyZjI5Ogd1YTA6E3Bhc3N3b3JkX3Rva2Vu%250AIi1jY2VmZmUzZDJkM2VkYjI1ZjkwMjdiNjVjMGJjNGY1NGIyM2VjMDNkIgpm%250AbGFzaElDOidBY3Rpb25Db250cm9sbGVyOjpGbGFzaDo6Rmxhc2hIYXNoewAG%250AOgpAdXNlZHsAOgdpZCIlZTA5OTQ3NTI3OTVhOTQ0MDk2NWY1NDIyM2UyZWIx%250ANDg%253D--9c753c78347f539059e1ed5ff8a572a5f50983da; __utmb=43838368.2.10.1320257591; __utmc=43838368
	1320257603.090388	C29z7G4daJC3Hbjok9	192.150.187.147	51749	199.59.149.198	80	4	POST	twitter.com	/scribe	http://twitter.com/	Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12	1863	1	200	OK	-	-	-	(empty)	-	-	-	F8LlgS3TjCQa88lku2	text/plain	Fj68Co2K0bJH7K2Gk6	application/octet-stream	__utmz=43838368.1308140498.28.11.utmcsr=nvie.com|utmccn=(referral)|utmcmd=referral|utmcct=/; __utma=43838368.1796737749.1282721850.1308206467.1320257591.30; __utmv=43838368.lang%3A%20en; guest_id=v1%3A13087319415918687; js=1; k=10.34.252.113.1320105621891535; original_referer=padhuUp37zi4XoWogyFqcGgJdw%2BJPXpx; auth_token=cceffe3d2d3edb25f9027b65c0bc4f54b23ec03d; twll=l%3D1320257295; lang=en; twid=u%3D403579461%7C1Rdt0%2FnmWmtcq3AHIcPk8%2BhHbh0%3D; _twitter_sess=BAh7DzoVaW5fbmV3X3VzZXJfZmxvdzA6DnJldHVybl90byJQaHR0cDovL3R3%250AaXR0ZXIuY29tL2FjY291bnQvY29uZmlybV9lbWFpbC9XdXJzdGZhY2h2ZXJr%250AdWYvQ0c3RDQtNUNGQzctMTMyMDI1Og9jcmVhdGVkX2F0bCsIEMN2ZTMBOhNz%250AaG93X2hlbHBfbGluazA6CXVzZXJpBEUiDhg6DGNzcmZfaWQiJWRlN2RmOGRj%250AMGJjMmRjNGQwNzkzYTRiMTNmNzUyZjI5Ogd1YTA6E3Bhc3N3b3JkX3Rva2Vu%250AIi1jY2VmZmUzZDJkM2VkYjI1ZjkwMjdiNjVjMGJjNGY1NGIyM2VjMDNkIgpm%250AbGFzaElDOidBY3Rpb25Db250cm9sbGVyOjpGbGFzaDo6Rmxhc2hIYXNoewAG%250AOgpAdXNlZHsAOgdpZCIlZTA5OTQ3NTI3OTVhOTQ0MDk2NWY1NDIyM2UyZWIx%250ANDg%253D--9c753c78347f539059e1ed5ff8a572a5f50983da; __utmb=43838368.2.10.1320257591; __utmc=43838368
	1320257604.977421	CfTPll20eWzTwj2Ra1	192.150.187.147	51757	208.122.62.226	80	1	GET	3347-mozilla.voxcdn.com	/pub/mozilla.org/firefox/releases/3.6.23/update/mac/en-US/firefox-3.6.23.complete.mar	-	Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12	0	300000	206	Partial Content	-	-	-	(empty)	-	-	-	-	-	F9Rs3e2YX1hpf1lzEg	application/octet-stream	-
	#close	2013-10-31-22-13-13

.. exercise::
    It turns out that Firesheep only uses a subset of the full list of cookie
    key-value pairs, namely those that identify the user session. For the
    remainder of this exercise, we mean this "sessionized" cookie when
    referring to a cookie. You may reuse our provided code that sessionizes the
    cookie.

    Your objective is now to check whether the cookie is seen with different
    user agents. Write code to track the user agent per cookie and raise a
    Notice if you see a different user agent than in the past. The current
    version of your script is `reuse2.bro <reuse2.bro>`_, which you can use
    as a starting point for this exercise. Test your script with the same trace
    `twitter.pcap <http://www.bro.org/static/traces/twitter.pcap>`_; your output should not generate more than a
    single Notice.

.. visible_solution::
    The file `reuse2-solution.bro <reuse2-solution.bro>`_ contains one possible
    solution.

    ::

	#separator \x09
	#set_separator	,
	#empty_field	(empty)
	#unset_field	-
	#path	notice
	#open	2013-10-31-22-31-43
	#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	fuid	file_mime_type	file_desc	proto	note	msg	sub	src	dst	p	n	peer_descr	actions	suppress_for	dropped	remote_location.country_code	remote_location.region	remote_location.city	remote_location.latitude	remote_location.longitude
	#types	time	string	addr	port	addr	port	string	string	string	enum	enum	string	string	addr	addr	port	count	string	table[enum]	interval	bool	string	string	string	double	double
	1320257580.095086	CX14Fy4OCprxwauBr5	192.150.187.147	51742	199.59.149.198	80	-	-	-	tcp	HTTP::SessionCookieReuse	Reused Twitter session via cookie _twitter_sess=BAh7DzoVaW5fbmV3X3VzZXJfZmxvdzA6DnJldHVybl90byJQaHR0cDovL3R3%250AaXR0ZXIuY29tL2FjY291bnQvY29uZmlybV9lbWFpbC9XdXJzdGZhY2h2ZXJr%250AdWYvQ0c3RDQtNUNGQzctMTMyMDI1Og9jcmVhdGVkX2F0bCsIEMN2ZTMBOgl1%250Ac2VyaQRFIg4YOgxjc3JmX2lkIiVkZTdkZjhkYzBiYzJkYzRkMDc5M2E0YjEz%250AZjc1MmYyOToHdWEwOhNwYXNzd29yZF90b2tlbiItY2NlZmZlM2QyZDNlZGIy%250ANWY5MDI3YjY1YzBiYzRmNTRiMjNlYzAzZDoHaWQiJWUwOTk0NzUyNzk1YTk0%250ANDA5NjVmNTQyMjNlMmViMTQ4IgpmbGFzaElDOidBY3Rpb25Db250cm9sbGVy%250AOjpGbGFzaDo6Rmxhc2hIYXNoewAGOgpAdXNlZHsAOhNzaG93X2hlbHBfbGlu%250AazA%253D--e71d494cec5e331a0c75022a30ad32a5ee6c731b; auth_token=cceffe3d2d3edb25f9027b65c0bc4f54b23ec03d	-	192.150.187.147	199.59.149.198	80	-	bro	Notice::ACTION_LOG	600.000000	F	-	-	-	-	-
	#close	2013-10-31-22-31-43

Part 2: Building a Facebook Webchat Analyzer
============================================

The webchat of Facebook is a feature that allows you to chat with your friends
while having a Facebook window open in the browser. In this exercise, we learn
how to use high-level data structures in Bro to represent such custom protocols
inside of HTTP.

Behind the scenes, the webchat utilizes a long-lived AJAX connection to
transfer the incoming and outgoing messages. A user that logs in to Facebook
automatically opens such a connection, destined to
``^([0-9]+\.)+channel\.facebook.com$``, to receive asynchronous status updates
(e.g., notifications that your friends are currently typing). Whenever Facebook
wants to notify you, it encodes a message as JSON object and ships it back to
you as JavaScript code, which may look like this::

    for (;;);{"t":"msg","c":"p_100002331422524","s":33,"ms":[{
        "msg":{"text":"You used the same IV as before????",
        "time":1303218869728,"clientTime":1303218869270,"msgID":"2665942259"},
        "from":100002331422524,"to":100002297942500,"from_name":"Mondo Cheeze",
        "from_first_name":"Mondo","from_gender":2,"to_name":"Udder Kaos",
        "to_first_name":"Udder","to_gender":2,"type":"msg"}]}

Your goal is to extract the messages from a Facebook webchat conversation and
put them into high-level Bro data structures where they are easy to manipulate,
print, and work with. After all, who wants to write boilerplate code whose only
purpose is to fight the *representation of the data* rather than analyzing the
data itself?

.. exercise::
    First off, download the script `bodies.bro <bodies.bro>`_ which reassembles
    the HTTP body of connections involving a given host. It provides a new
    event ``http_event`` that has the full HTTP body as argument. (Without that
    script, you would have to reassemble that body from the individual
    ``http_entity_*`` events.)

    Next, download the scaffold of the Facebook analyzer `facebook.bro
    <facebook.bro>`_, which you will work with in this exercise. The script
    contains a function::

       function parse_fb_message(data: string) : ChatMessage

    which takes a big string and converts into a record ``ChatMessage``. Your
    job is finish writing this function. To this end, you need to extract the
    values ``time``, ``from_name``, ``to_name``, and ``text`` from the JSON
    object inside the HTTP body.

    After having finished the implementation, run your script on the trace
    `url.pcap`_ and look at the output. Extra credit: can you reconstruct the
    encrypted URL?

    .. note::
        You may find the following string procssing functions useful:

        - ``sub(str: string, re: pattern, repl: string): string``

            Substitute once the pattern ``re`` with the string ``repl`` in
            ``str`` and return the new string. The function ``gsub`` has the
            same signature and replace *all* occurences of ``re`` in ``str``
            with ``repl``.

        - ``sub_bytes(s: string, start: count, n: int): string``

            Obtain a substring of ``s`` that starts at position ``start`` and
            has length ``n``.

        - ``strstr(big: string, little: string): count``

            Locates the first occurrence of the string ``little`` in ``big``.
            Returns 0 if ``little`` is not found in ``big``.

        - ``find_last(str: string, re: pattern) : string``

            Returns the last occurrence of the given pattern in the given
            string.

.. visible_solution::
    The script `facebook-solution.bro <facebook-solution.bro>`_ contains one
    possible solution and will produce a new facebook.log file with the following
    content:

    ::

	#separator \x09
	#set_separator	,
	#empty_field	(empty)
	#unset_field	-
	#path	facebook
	#open	2013-10-31-22-39-21
	#fields	timestamp	chat_from	chat_to	chat_msg
	#types	string	string	string	string
	1303218454567	Mondo Cheeze	Udder Kaos	So I need the URL, dude.  What is it?
	1303218465938	Udder Kaos	Mondo Cheeze	the URL?
	1303218474259	Mondo Cheeze	Udder Kaos	Yeah for the secret image
	1303218481721	Udder Kaos	Mondo Cheeze	ok lemme see
	1303218495626	Mondo Cheeze	Udder Kaos	Someone could be sniffing this conversation, be sure to send it safely
	1303218503972	Udder Kaos	Mondo Cheeze	?
	1303218570782	Mondo Cheeze	Udder Kaos	Cmon we talked about this.  Encrypt it with WonderCipher-92 and send me the Base64 encoding of the hex.  Usual key.
	1303218587568	Udder Kaos	Mondo Cheeze	'k.  So here it is:
	1303218595067	Udder Kaos	Mondo Cheeze	NmQwMDJjZDdhZTdlYmYxNTc5MGVjZDc1YTYxNDk1OGE0ZTRhYjAzOTVi
	1303218618252	Mondo Cheeze	Udder Kaos	What's the IV
	1303218624712	Udder Kaos	Mondo Cheeze	huh?
	1303218637197	Mondo Cheeze	Udder Kaos	Initialization vector, you maroon.  WC-92 is a stream cipher, you know
	1303218667601	Udder Kaos	Mondo Cheeze	oh yeah.  I used my birthday, all as one number.
	1303218685436	Udder Kaos	Mondo Cheeze	you *do* remember it, right?
	1303218700515	Mondo Cheeze	Udder Kaos	yeah your an April Fool, not hard to remember
	1303218710402	Udder Kaos	Mondo Cheeze	heh
	1303218718486	Mondo Cheeze	Udder Kaos	K gimme a sec to decrypt then.
	1303218733463	Mondo Cheeze	Udder Kaos	Hey idiot this isn't the secret, it's Google's home page.
	1303218745028	Udder Kaos	Mondo Cheeze	whoops hang on, blew my cut&paste
	1303218767633	Udder Kaos	Mondo Cheeze	okay, here's the right one:
	1303218776922	Udder Kaos	Mondo Cheeze	NmQwMDJjZDdhZTdlYmYwMDY3MGRjZDdlYjA1NDlhODQ0ZjA1YmEyNDRm
	1303218800303	Mondo Cheeze	Udder Kaos	And?
	1303218807537	Udder Kaos	Mondo Cheeze	and what
	1303218815022	Mondo Cheeze	Udder Kaos	What's the IV
	1303218824330	Udder Kaos	Mondo Cheeze	huh?
	1303218839537	Mondo Cheeze	Udder Kaos	yo maroon same thing as we just discussed a moment ago, sheesh
	1303218855518	Udder Kaos	Mondo Cheeze	oh that yeah like I said my birthday
	1303218869728	Mondo Cheeze	Udder Kaos	You used the same IV as before????
	1303218889893	Udder Kaos	Mondo Cheeze	right, otherwise how would I remember it?
	1303218900257	Mondo Cheeze	Udder Kaos	YOU BOZO
	#close	2013-10-31-22-39-23

    Here is the solution for the extra credit question: Udder Kaos has
    no idea about cryptography. Reusing the same initialization vector (IV)
    twice can have fatal consequences when using a stream cipher. Let us define
    some variables and functions::

        B64D := function that decodes a Base64 encoded string
        P1   := "http://www.google.com"
        P2   := (unknown)
        C1   := B64D(NmQwM...zOTVi)
        C2   := B64D(NmQwM...mNDRm)
        ⊕    := XOR operation

    Let *R* denote the keystream for the reused IV. An eavesdropper now
    computes::

        C1 ⊕ C2 = (P1 ⊕ R) ⊕ (P2 ⊕ R) = P1 ⊕ P2

    which is equivalent to::

         P2 = C1 ⊕ C2 ⊕ P1.

    Plugging in the values from above, we find that ``P2`` equals
    http://bit.ly/hbdairy. The code snippet below does exactly this
    computation:

    .. code::
        #!/usr/bin/env ruby

        require 'base64'

        PLAINTEXT = 'http://www.google.com'

        enc1 = 'NmQwMDJjZDdhZTdlYmYxNTc5MGVjZDc1YTYxNDk1OGE0ZTRhYjAzOTVi'
        enc2 = 'NmQwMDJjZDdhZTdlYmYwMDY3MGRjZDdlYjA1NDlhODQ0ZjA1YmEyNDRm'

        C1 = Base64.decode64(enc1)
        C2 = Base64.decode64(enc2)
        P1 = PLAINTEXT.scan(/./).map { |x| x[0].to_s(16) } * ''

        p1, c1, c2 = [P1, C1, C2].map { |a| a.scan(/../) }  # Array of hex bytes.

        # Zip the arrays together so that we can process them three bytes at a time.
        # We "reduce" this three-element array by XORing (operator ^) its elements.
        p2 = p1.zip(c1, c2).map { |three| three.map { |byte| byte.hex }.reduce(:^) }

        # Go back to text representation and join (operator *) the array of characters.
        p2 = p2.map { |h| h.chr } * ''
        puts(p2)

    If we follow the link, we see the mighty master mind of Synonymous. (Well,
    the original link no longer resolves. But http://bit.ly/hbdairy2 does.)
