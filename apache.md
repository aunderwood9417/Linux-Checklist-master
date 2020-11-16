# Underwood's Apache Checklist

## Notes

Assume root permissions are needed for most commands.

If Apache is required on the image, please follow this checklist. Otherwise, disable Apache.

## Apache Basics

`/etc/apache/apache2.conf` is the main configuration file on Debian and Ubuntu

Default root directory:

	/var/www/html or /var/www

Test config file syntax

	$ http -t

Access logs

	/var/log/httpd/access_log` and `/var/log/httpd/ssl_access_log

Error logs

	/var/log/httpd/error_log

## Checklist

1. Update `apache2` to the latest version

	`$ apt-get install apache2`

1. Run Apache as a separate user and group

	1. Create Apache user and group

		`$ groupadd apache-web`

		`$ useradd -d /var/www/ -g apache-web -s /bin/nologin apache-web`

	1. Set "User" and "Group" in `/etc/apache/apache2.conf` to `apache-web`

		```
		User apache-web
		Group apache-web
		```

1. Start the Apache service

	1. If using systemd

		`$ service apache2 start`

	1. If using Upstart

		`$ /etc/init.d/apache2 start`

1. Audit the existing Apache installation

	1. See what the website currently looks like

		`$ wget 127.0.0.1`

	1. Look through and backup the `/var/www` directory

		`$ ls -l /var/www`

		`$ rsync -avzh /var/www <destination>`
