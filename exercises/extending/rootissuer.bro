redef record SSL::Info += {
	root_issuer: string &log &optional;
};

event x509_certificate(c: connection, is_orig: bool, cert: X509, chain_idx: count, chain_len: count, der_cert: string)
	{
	c$ssl$root_issuer = cert$issuer;
	}
