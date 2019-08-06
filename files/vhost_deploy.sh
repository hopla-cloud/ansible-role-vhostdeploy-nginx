#!/bin/bash
# Script Version 2.3-nginx (01-08-2018)
# Written by rmeillon@iilyo.com

# Admin user for folder rights (example : ii0001)
adminUser="iiXXXX"
adminEmail="admin@customer.com"

# Nginx Configuration
nginxGroup="www-data"
nginxConfPrefix="/etc/nginx"
sitesPathPrefix="/var/www/sites"

# PHP-FPM Configuration (5.6, 7.0, 7.1, 7.2)
phpfpmDaemonName="php7.2-fpm"
phpfpmPoolPrefix="/etc/php/7.2/fpm/pool.d"

# FTP Configuration
ftpShellPath="/usr/local/bin/ftponly"

# Put the date into a var
dateLog=$(date +%Y%m%d-%H%M)

# check if we are root or not
WHOISIT=`whoami`
[ $WHOISIT != 'root' ] && echo "Ce script doit être lancé avec sudo." && exit 1
# Check if the FQDN length is not too long
# Limitation on 32 chars for the unix username
function checkLength {
	futureUser=$2$(echo $1 | tr -d '-' | tr -d '.' | cut -c -13)
	if [ ${#futureUser} -ge 32 ]
	then
		return 1
	fi
}
# Just check if the vhost folder exists or not
function checkFolder {
	if [ -d ${sitesPathPrefix}/$1/$2 ]
	then
		return 1
	fi
}

# Generate a password a create a system user
function addSysUser {
	newpass=""
	ranlist1="BCDFGHJKLMNPQRSTVWXZ"
	ranlist2="bcdfghjklmnpqrstvwxz"
	ranlist3="aeiou"
	ranlist4="0123456789"
	passChar1=$(echo ${ranlist1:$(($RANDOM%${#ranlist1})):1})
	passChar2=$(echo ${ranlist3:$(($RANDOM%${#ranlist3})):1})
	passChar3=$(echo ${ranlist2:$(($RANDOM%${#ranlist2})):1})
	passChar4=$(echo ${ranlist3:$(($RANDOM%${#ranlist3})):1})
	passChar5=$(echo ${ranlist4:$(($RANDOM%${#ranlist4})):1})
	passChar6=$(echo ${ranlist4:$(($RANDOM%${#ranlist4})):1})
	passChar7=$(echo ${ranlist4:$(($RANDOM%${#ranlist4})):1})
	passChar8=$(echo ${ranlist4:$(($RANDOM%${#ranlist4})):1})
	newpass=$passChar1$passChar2$passChar3$passChar4!$passChar5$passChar6$passChar7$passChar8
	user=$2$(echo $1 | tr -d '-' | tr -d '.' | cut -c -13)
	
	# Old Algo
	# newpass=`date +%s | sha256sum | base64 | head -c 10 ; echo`
	# user=$(echo $2.$1 | cut -c -15)
	
	useradd -M --home-dir ${sitesPathPrefix}/$1/$2 -s ${ftpShellPath} $user
	echo $user:$newpass | chpasswd
	echo "+-----------------------------------+"
	echo "|            FTP Login              |"
	echo "+-----------------------------------+"
	echo "UserName : $user"
	echo "Password : $newpass"
	echo "+-----------------------------------+"
}

# Delete system user
function deleteSysUser {
	#user=$(echo $2.$1 | cut -c -15)
	user=$2$(echo $1 | tr -d '-' | tr -d '.' | cut -c -13)
	userdel $user
}

# Create vhost folders with the good rights
function createFolders {
	#user=$(echo $2.$1 | cut -c -15)
	user=$2$(echo $1 | tr -d '-' | tr -d '.' | cut -c -13)

	mkdir -p ${sitesPathPrefix}/$1/$2
	[ $? == 0 ] || return 1

	chown ${adminUser}:${nginxGroup} ${sitesPathPrefix}/$1
	chown ${user}:${user} ${sitesPathPrefix}/$1/$2
	chmod 755 ${sitesPathPrefix}/$1
	chmod 775 ${sitesPathPrefix}/$1/$2
}

# Delete vhost folders
function deleteFolders {
	rm -f ${sitesPathPrefix}/$1/$2.info-host

	#rm -rf ${sitesPathPrefix}/$1/$2
	#[ "$(ls -A ${sitesPathPrefix}/$1)" ] && echo "An other subdomain exits, ${sitesPathPrefix}/$1 is still here" || rm -rf ${sitesPathPrefix}/$1
	[ $? == 0 ] || return 1
	return 0
}

# Create a PHP-FPM pool dedicated to this vhost
function createFpmPool {
user=$2$(echo $1 | tr -d '-' | tr -d '.' | cut -c -13)

cat > ${phpfpmPoolPrefix}/$1_$2.conf << EOF
[$1_$2]
user = $user
group = $user
listen = /run/php/php7.1-fpm-$1_$2.sock
listen.owner = nginx
listen.group = nginx
pm = dynamic
pm.max_children = 10
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
pm.max_requests = 500
request_terminate_timeout = 240
security.limit_extensions = .php .php3 .php4 .php5 .php7
EOF
}

# Delete a PHP-FPM pool
function deleteFpmPool {
	rm -f ${phpfpmPoolPrefix}/$1_$2.conf
}

# Kill the processus lanched by a system user (ex : FTP Session)
function stopUserProcesses {
	user=$2$(echo $1 | tr -d '-' | tr -d '.' | cut -c -13)
	killall -user $user
}

# Delete Nginx vhost configuration
function deleteConfig {
	rm -rf ${nginxConfPrefix}/conf.d/$1_$2*.conf
	[ $? == 0 ] || return 1
	# reload nginx
	rm -rf /var/log/nginx/$1_$2_error.log*
	[ $? == 0 ] || return 1
	rm -rf /var/log/nginx/$1_$2_access.log*
	[ $? == 0 ] || return 1
	# empty folder may be removed also
	return 0
}

# Create the vhost info file
function addHostInfo {
	user=$2$(echo $1 | tr -d '-' | tr -d '.' | cut -c -13)
	touch ${sitesPathPrefix}/$1/$2.info-host
	chown $adminUser:$nginxGroup ${sitesPathPrefix}/$1/$2.info-host
	echo "Domain: $2.$1
User: $user
Webdir: ${sitesPathPrefix}/$1/$2
Deploy Date: $dateLog" > ${sitesPathPrefix}/$1/$2.info-host
}

# Create the nginx vhost configuration
function createNginxConf {
user=$(echo $2.$1 | cut -c -15)
cat > ${nginxConfPrefix}/conf.d/$1_$2.conf << EOF
#server {
#    listen 80;
#    server_tokens off;
#    server_name $2.$1;
#    root ${sitesPathPrefix}/$1/$2;
#    location / {
#        rewrite     ^(.*)   https://$2.$1\$1 break;
#    }
#    access_log off;
#    log_not_found off;
#}

server {
    #listen 443 ssl;
	listen 80;
    server_name $2.$1;
    server_tokens off;

    #ssl_certificate /etc/xxx/fullchain.pem;
    #ssl_certificate_key /etc/xxx/privkey.pem;
    #ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    #ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';
    #ssl_prefer_server_ciphers on;
    #ssl_session_cache shared:SSL:30m;

    root ${sitesPathPrefix}/$1/$2;
    index index.php;

    access_log      /var/log/nginx/$1_$2_access.log;
    error_log       /var/log/nginx/$1_$2_error.log;

    location / {
        # try to serve file directly, fallback to index.php
        try_files $uri /index.php$is_args$args;
    }

    location ~ ^/index\.php(/|$) {
        fastcgi_pass unix:/var/run/php/php7.1-fpm-$1_$2.sock;
        fastcgi_split_path_info ^(.+\.php)(/.*)$;
        include fastcgi_params;

        # optionally set the value of the environment variables used in the application
        # fastcgi_param APP_ENV prod;
        # fastcgi_param APP_SECRET <app-secret-id>;
        # fastcgi_param DATABASE_URL "mysql://db_user:db_pass@host:3306/db_name";

        # When you are using symlinks to link the document root to the
        # current version of your application, you should pass the real
        # application path instead of the path to the symlink to PHP
        # FPM.
        # Otherwise, PHP's OPcache may not properly detect changes to
        # your PHP files (see https://github.com/zendtech/ZendOptimizerPlus/issues/126
        # for more information).
        fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
        fastcgi_param DOCUMENT_ROOT $realpath_root;
        # Prevents URIs that include the front controller. This will 404:
        # http://domain.tld/index.php/some-path
        # Remove the internal directive to allow URIs like this
        internal;
    }

    # return 404 for all other php files not matching the front controller
    # this prevents access to other php files you don't want to be accessible.
    location ~ \.php$ {
        return 404;
    }

    # Security. discard all files and folders starting with a "."
    location ~ /\. {
        deny  all;
        access_log off;
        log_not_found off;
    }
    # Stuffs
    location = /favicon.ico {
        allow all;
        access_log off;
        log_not_found off;
    }
    location ~ /robots.txt {
        allow  all;
        access_log off;
        log_not_found off;
    }

    # Static files
    location ~* ^.+\.(jpg|jpeg|gif|css|png|js|pdf|zip)$ {
        expires     30d;
        access_log  off;
        log_not_found off;
    }
}



server {
    listen 80;
    server_name $2.$1;
	server_tokens off;
	
#    ssl on;
#    ssl_certificate /etc/xxx/fullchain.pem;
#    ssl_certificate_key /etc/xxx/privkey.pem;
#    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
#    ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';
#    ssl_prefer_server_ciphers on;
#    ssl_session_cache shared:SSL:30m;

    root ${sitesPathPrefix}/$1/$2;
    index index.php;

    access_log      /var/log/nginx/$1_$2_access.log;
    error_log       /var/log/nginx/$1_$2_error.log;

#    location / {
#        # try to serve file directly, fallback to app.php
#        try_files $uri /app.php$is_args$args;
#    }

        # Php configuration     
        location ~ [^/]\.php(/|$) {
        
        fastcgi_split_path_info ^(.+?\.php)(/.*)$;
        if (!-f \$document_root\$fastcgi_script_name) {
          return 404;
        }
        
        # Mitigate https://httpoxy.org/ vulnerabilities
        fastcgi_param HTTP_PROXY "";

        fastcgi_pass unix:/var/run/php/php7.1-fpm-$1_$2.sock;

        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root/\$fastcgi_script_name;
        }
	location ~ \.php$ {
      return 404;
    }

    # Security. discard all files and folders starting with a "."
    location ~ /\. {
        deny  all;
        access_log off;
        log_not_found off;
    }
    # Stuffs
    location = /favicon.ico {
        allow all;
        access_log off;
        log_not_found off;
    }
    location ~ /robots.txt {
        allow  all;
        access_log off;
        log_not_found off;
    }

    # Static files
    location ~* ^.+\.(jpg|jpeg|gif|css|png|js|pdf|zip)$ {
        expires     30d;
        access_log  off;
        log_not_found off;
    }
}
EOF

}

case $1 in
        create)
			if [[ -n $2 && -n $3 ]]
			then
					checkLength $2 $3
					[ $? != 0 ] && echo "La combinaison du nom de domaine et du sous-domaine sont trop longs. Vous pouvez indiquer un sous-domaine plus petit et modifier ensuite le vhost, ou trouver un sous-domaine plus court." && exit 1
					#printf "Check Folder\n"
					checkFolder $2 $3
					[ $? != 0 ] && echo "Le dossier du domaine $3.$2 existe déjà." && exit 1
					#printf "Add System User\n"
					addSysUser $2 $3
					#printf "Create Folder\n"
					createFolders $2 $3
					#printf "Add Host Info File\n"
					#addHostInfo $2 $3
					#printf "Create PHP-FPM Conf\n"
					createFpmPool $2 $3
					#printf "PHP-FPM Reload\n"
					systemctl reload ${phpfpmDaemonName}
					#printf "Create Nginx Conf\n"
					createNginxConf $2 $3
					#printf "Nginx Reload\n"
					systemctl reload nginx
					exit 0
			else
				echo "Erreur : Vous devez indiquer un nom de domaine et un sous domaine."
				exit 1
			fi
        ;;

		delete)
			if [[ -n $2 && -n $3 ]]
			then
					#printf "Check Folder\n"
					checkFolder $2 $3
					[ $? != 1 ] && echo "Le domaine $3.$2 n'existe pas." && exit 1
					#printf "Delete Config\n"
					deleteConfig $2 $3
					#printf "Delete PHP-FPM Pool\n"
					deleteFpmPool $2 $3
					#printf "PHP-FPM Reload\n"
					systemctl reload ${phpfpmDaemonName}
					#printf "killing user processes\n"
					stopUserProcesses $2 $3
					#printf "Delete User\n"
					deleteSysUser $2 $3
					#printf "Nginx Reload\n"
					systemctl reload nginx
					#printf "Delete Folders\n"
					deleteFolders $2 $3
					exit 0
			else
				echo "Erreur : Vous devez indiquer un nom de domaine et un sous domaine."
				exit 1
			fi
		;;
		
        *)
		echo "Usage : $0 create|delete <nom de domaine> <sous-domaine>"
		exit 1
        ;;
esac
