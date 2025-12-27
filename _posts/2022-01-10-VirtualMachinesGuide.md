---
layout: post
title: Introduction to Virtual Machines
tags: [Maquinas Virtuales, Guia, English, Windows]
description: Guide of how to install and configure a Virtual Machine with Oracle VirtualBox.
categories: [en, Guias]
---

A guide of how to install and configure a **Virtual Machine** with **Oracle VirtualBox**. In this case, we'll set up a **Windows 7 Virtual Machine** and configure it.

<br>

<p align="center">
    <img src="/img/vms/2022-01-07-14-14-45.png">
</p>

<br>

## Table of Content
- [1. What's Virtualization?](#1)
  - [1.1 Why virtualize?](#11)
  - [1.2 What we need to Virtualize?](#12)
  - [1.3 Limitations while virtualizing](#13)
- [2. Installation and setting up](#2)
  - [2.1 Activating the virtualization](#21)
  - [2.2 Installing the required Software (Oracle VirtualBox)](#22)
- [3. Creating a VM (Virtual Machine)](#3)
  - [3.1 Setting up the VM](#31)
  - [3.2 Preparing the minimum configuration before start the machine](#32)
  - [3.3 Preparing the ISO file](#33)
  - [3.4 Installing the OS](#34)
- [4. Guest Additions and Extension Pack](#4)
  - [4.1. Installing the Extension Pack](#41)
  - [4.2. Setting up the Guest Additions](#42)
  - [4.3. Guest Additions features](#43)
    - [4.3.1. Shared Clipboard](#431)
    - [4.3.2. Shared Folder](#432)
    - [4.3.3. USB into a VM](#433)
- [5. Network configuration](#5)
  - [5.1. Bridged Adapter](#51)
  - [5.2. NAT](#52)
  - [5.3. NAT Network](#53)

<br>

<br>

## 1. What's Virtualization? <a id=1></a>

Virtualization is the process of running a **virtual environment inside a computer**. With the virtualization, it's possible to run a completely isolated Operating System inside another one. 

### 1.1 Why virtualize? <a id=11></a>

Imagine you have a Windows 10 machine (Physical machine) and the new Windows 11 has been released. Now you have three options if you want to test it:

- Make Windows 11 your main Operating System
- Make a Dual Boot with Windows 10 and Windows 11
- Create a Virtual Machine to test it

> A Dual Boot is when you have two OS installed inside a Computer. When it start, you'll be asked what OS you want to run.

If you want to test it, you may not want to install it as your main OS: it'll overwrite you Windows 10 and, if you don't want to make it your main OS (And change again to Windows 10), there could be problems.

The Dual Boot option could be a good one, but if you want to remove Win11 later, there could be complications if you are not sure about what you are doing.

If we use a VM to test it, we could test it without interfering in our main OS, create Snapshots (Points that can be loaded if something wrong happens in the VM), change many options such as the maximum of RAM, processors and Network Adapter and delete it whenever we want.

We can also use it to test ANY OS (Including Windows 1.0 or the first Linux Distro), either 32 or 64 Bits. You can even test how a Malware behaves without infecting your main OS (As long as the VM is not connected to the Network because it could be infected!)

### 1.2 What we need to Virtualize? <a id=12></a>

To virtualize, we need:

- A software to Virtualize (Like VirtualBox or VMWare)
- The Virtualization Option enabled in our CPU (Can be activated in the BIOS)
- The .ISO file of the OS.
- Meet the minimum OS requirements

We'll se all this below.

### 1.3 Limitations while virtualizing <a id=13></a>

While Virtualizing, we have to keep in mind that each OS has its minimum requirements and we have to meet our main OS requirements plus the VM OS: 

If we have a Win10 that needs 2GB of RAM and we want to install another OS that needs another 2GB, it'll consume a total of 4GB. If our physical machine only has 4GB of RAM, it won't run properly, so, in that case, could be better to install a 32 Bits OS instead a 64 Bits OS because it needs less resources to run.

<br>

## 2. Installation and setting up <a id=2></a>

Then, knowing this, let's start setting up the necessary to virtualize...

### 2.1 Activating the virtualization <a id=21></a>

First of all, we need to activate the virtualization option within the BIOS...

> Depending on the BIOS version and motherboard manufacturer, the BIOS UI (User Interface) will look different and the name or the location of the option that we're looking for could change.

To enter BIOS, turn off the computer and press the key that appear on one of the sides of the screen. (Usually F2, F7, F11, CTRL + ALT + [F1 - F12]...) 

Be careful! Many BIOS options are advanced ones and, if you are not sure about what they do, do not modify it.

![](/img/vms/BIOS.jpg)

To exit the BIOS, there will be an option to Restart the computer or just to exit the BIOS (Depending the version).

### 2.2 Installing the required Software (Oracle VirtualBox) <a id=22></a>

Once virtualization has been activated, we can install the Software to Virtualize. In this case, we'll install Oracle VirtualBox. 

To install it, just enter [this link](https://www.virtualbox.org/wiki/Downloads), choose your Operating System (In my case, Windows) and the download should start. 

Open the executable and follow the installer steps (Next, next, next...). While installing it, the internet connection could be stopped for a moment.

<br>
<br>

## 3. Creating a VM (Virtual Machine) <a id=3></a>

### 3.1 Setting up the VM <a id=31></a>

Now, it's time to create a Virtual Machine. In my case, I'll create a Windows 7 (64 Bits) machine.

Let's start opening VirtualBox...

![](/img/vms/vbox.png)

Then, press `New` (At the top of the screen) and enter the machine name and the OS.

![](/img/vms/create.png)

After that, press `Next` and select the maximum amount of RAM that the VM can use (Keep in mind the OS minimum requirements and your physical amount).

![](/img/vms/RAM.png)

Press `Next` and you will be asked to choose the Hard Disk: 

| Option | Description |
| ----- | ----------- |
| Do not add a virtual Disk | Please don't do that unless you want to create it after. |
| Create a Virtual Hard Disk | Create a new disk file to store the machine data. |
| Use and existing Virtual Hard Disk file | Use an existing Disk file to store the machine data. If there are data inside this file, it should be used in the new machine. |

Choose whatever you want/need. In my case, I will create a new Disk File.

Press `Create` and now you will be asked about the Disk Type. There are three types. Personally, I chose the first one because I only use VirtualBox. If you'll use another Software after the installation, choose another one.

![](/img/vms/disk.png)

After that, press `Next` and you'll can choose between two types of Disk:

| Type | Description |
| ---- | ----------- |
| Dynamically allocated | The maximum disk size is fixed but the file weight will be only that it contains. |
| Fixed Size | The file will allways weight the maximum of the disk. |

Pros and cons of each Disk Type

→ Dynamic 

| Pros | Cons |
| ---- | ---- |
| Requires less space in Disk (The file weight will be smaller than the Fixed Size Disk). | Its slower than the other. |

→ Fixed

| Pros | Cons |
| ---- | ---- |
| Its faster than the dynamic one. | Weighs more than the other. |

We can choose whatever disk we want according to our needs. In my case, I'll choose a Dynamic Disk because I don't need a lot of speed and I don't want the disk occupies lot of space.

After that, we can choose the file location and its size. I recommend to choose a bit more of the recommended size.

![](/img/vms/size.png)

Press `Create` and the machine will be created.

### 3.2 Preparing the minimum configuration before start the machine <a id=32></a>

First of all, we need to do some small configurations in order to start the machine properly:

Right click in the VM and press `Settings`. Then, a configuration Window will be open:

- We can disable the `Floppy` (It's almost deprecated)

![](/img/vms/floppy.png)

- We can set the amount of CPUs

![](/img/vms/cpus.png)

Now, we have to install and set up the ISO file in order to run the machine.

### 3.3 Preparing the ISO file <a id=33></a>

We have to Download the ISO of our Operating System. To do it, just search it on Google (Please download it from the official website) and download the version of the OS. In my case, I'll download the Windows 7 ISO file from [here](https://www.microsoft.com/en-US/download/details.aspx?id=46078).

Once installed, open VirtualBox and start the machine. You'll be asked for the ISO. Just Select it and press `Start`.

### 3.4 Installing the OS <a id=34></a>

Now, its time to install the OS. In many cases, the installation will be "Next, Next, Next..." (Unless you're installing Arch Linux or something related 😄). 

When we're asked to choose the OS version, select whatever you want and choose between 32 and 64 Bits. 

![](/img/vms/versionwin.png)

In the partitions configuration, unless you need more than the main partition, press `Next`.

Then, the installation will start...

![](/img/vms/install.png)

We have to wait until it finish and then, we'll be asked for our username, PC name, passwords, activations keys...

![](/img/vms/name.png)

> When it ask us to enter a product key, we've to skip it (It's a VM. You may do not need to activate Windows here)

Once the installation finish, the OS will be ready!

<br>

## 4. Guest Additions and Extension Pack<a id=4></a>

Now, the VM has been installed, but there are some extra features that we can add in order to enhance our experience: the Extension Pack (for the whole VirtualBox) and the Gust Additions (In each machine).

### 4.1. Installing the Extension Pack<a id=41></a>

The first thing we need to install is the **Extension Pack** for our VirtualBox Version:

> Before that, we need to get our VBox version: Help > About Virtualbox

Now, having our VBox version, we'll go to the [VBox releases](https://www.virtualbox.org/wiki/Download_Old_Builds_5_2) and we'll search our version.

> If we have the latest version, just we can go to the [VBox Downloads](https://www.virtualbox.org/wiki/Downloads), Extension Pack, and Download the latest release.

- VirtualBox Version

![](/img/vms/2022-01-18-18-18-17.png)

- If we have the latest version

![](/img/vms/2022-01-18-18-23-09.png)

- If our version is older, we'll have to search it within the [VBox Page](https://virtualbox.org). For example, if my version is 5.2.6, I'll find my Extension Pack here: `https://www.virtualbox.org/wiki/Download_Old_Builds_5_2`

> You can use `CTRL + F` to find your version faster.

![](/img/vms/2022-01-18-18-41-09.png)

Once downloaded, open VBox, go to preferences, Extensions and Add New Package. Then, select the Extension Pack File and the installation wizard will be open. Press Next until the installation starts.

> Once installed, it should looks like the image:

![](/img/vms/2022-01-18-20-16-11.png)

### 4.2. Setting up the Guest Additions<a id=42></a>

Now, we have to start up our Virtual Machine...

Go to the File Explorer (`Win + E`) and to `This PC`. Then, go to the above menu, press `Device` and `Insert Guest Additions CD Images...`.

![](/img/vms/2022-01-18-20-39-47.png)

Now, an External Drive should be 'connected' to de machine. Double click on it and the installation wizard should start. Press `Next` until the installation starts.

> If the Hard Drive opens as a folder, you'll have to choose the wizard version for your the current OS.

![](/img/vms/2022-01-18-20-59-55.png)

Once installed, it'll ask us to reboot now or later... Press whatever option you want, but keep in mind that the changes do not will apply unless the system restarts.

> Also keep in mind that you have to repeat this process in each machine you want to have the Guest Additions installed (Just this, not the Extension Pack installation).

### 4.3. Guest Additions features<a id=43></a>

Once the system is restarted. The features will be applied.

Some of the Guest Additions features are:

#### 4.3.1. Shared Clipboard<a id=431></a>

We can activate the `Shared Clipboard` option. It allow us to copy and paste between the host (Main OS) and the guest (Virtualized OS).

![](/img/vms/clipboard.png)

#### 4.3.2. Shared Folder<a id=432></a>

We can enable a Shared Folder between the Host and the Guest. To do it, go to `Settings` (It isn't necessary to stop the VM) and go to `Shared Folders`...

![](/img/vms/2022-01-18-21-21-34.png)

- Right click in `Machine Folder` and press `Add Shared Folder`.

![](/img/vms/2022-01-18-21-29-35.png)

- Select the path to create the Shared Folder (In the Host)

- Mark the `Auto-Mount` and `Make Permanent` options.

- Choose a unit (letter) where to mount it (In my case, I've chosen the `z:`)

- Press `OK`

![](/img/vms/2022-01-18-21-33-55.png)

Now, if we go to `Z:\`, we'll see the shared folder. If something is created in that folder using the guest, the host can see it, and vice versa.

> I've created a file and a folder with the Guest and the Host. 

![](/img/vms/2022-01-18-21-42-48.png)


#### 4.3.3. USB into a VM<a id=433></a>

Now, imagine we have a USB connected to our PC (physical machine) and we want to access it onto the VM. If we go to the file explorer, we won't see it unless we enable the option. In order to do it:

- Go to Settings > USB.

- Enable the `Enable USB Controller` option. If we can't, just stop the machine.

![](/img/vms/2022-01-19-15-13-04.png)

![](/img/vms/2022-01-19-19-10-37.png)

- Right click and press `Add Filter From Device`

![](/img/vms/2022-01-19-15-15-18.png)

- Choose the USB...

![](/img/vms/2022-01-19-15-19-57.png)

> Before continue, make sure to choose the correct USB mode (1.1, 2.0 or 3.0). If you have choosen a type that does not match with your USB, it won't work.

- Start the VM. If it appear but you cannot access it, the problem should be the USB drivers.

If all it's OK, we should see the USB on `This PC` folder.

![](/img/vms/2022-01-19-19-05-23.png)


<br>

## 5. Network settings<a id=5></a>

There are many network settings (Like Bridged Adapter, NAT, NAT Network, Internal Network, Not Attached...), each used for an especific thing. Now, we'll see three of them:

![](/img/vms/netsettings.png)



### 5.1 Bridged Adapter<a id=51></a>

First, we'll start seeing the 'Bridged Adapter' mode. If we enable it, the VM will work as a Device connected directly to our Physical Network (Like if we connect a new device to our Network). 

![](/img/vms/2022-01-28-09-27-59.png)

The IP should be the same type of the Host. In my case, my host's **private IP address** is '192.168.1.182', and my VM's IP is '192.168.2.243' (Both IPs are type C. They're like '128.168.x.x'). Also, we have internet access and we can see other devices connected to the network (As long as we can see with our physical machine).

![](/img/vms/bridgeipconfig.png)

> As we can see in the image, we can ping 'google.com'. It means that we can connect to Internet with our VM.

A graphical representation of this mode:

![](/img/vms/2022-01-30-17-11-33.png)

This mode could be useful if we need to serve something (Like an HTTP Server, FTP Server, SSH Server...) inside a network because other hosts can connect to it. Also, it is possible to open a port in our router and forward it to our VM in order to serve something that can be accessed by other devices outside the network.

### 5.2 NAT<a id=52></a>

This is the default mode. If the NAT (Network Address Translation) mode is enabled, our VM will have a Type A IP address (Like 10.x.x.x). It'll allways have the same IP `10.0.2.15` and the same Default Gateway `10.0.2.2`.

![](/img/vms/2022-01-31-14-40-12.png)

![](/img/vms/2022-01-30-17-45-06.png)

With this mode enabled, the VM wll be able to see other devices inside the network and will have internet access, but these devices won't be able to see them. The outbound connections will be made from our Host IP address and the inbound connections will be routed to the Host, but the VBox NAT router will redirect the response to our VM. Also, a VM in NAT mode won't be able to see other VMs in NAT mode on the network: all of them will have the same IP addres `10.0.2.15`.

![](/img/vms/2022-01-30-18-13-55.png)

This mode could be useful if we want to do any task that does not require to serve any service to the other network devices. 

### 5.3 NAT Network<a id=53></a>

This mode is not the same as the NAT mode, but is similar: with this mode, one can create an internal NAT
network similar to the NAT mode, but being able to add other Virtual Machines to that network. 

![](/img/vms/2022-01-31-14-43-05.png)

All the VMs in that network will be able to see the other Virtual Machines as well as the devices connected to the physical network. Also, these VMs can access internet like the NAT mode.

The IP addresses will deppend on the range assigned when creating the NAT Network (See below). By default, the assigned IP range is `10.0.2.0/24` so a machine could have an IP like `10.0.2.4`, `10.0.2.15`...

Now, once explained, we'll see how to configure it and if it really works:

> In order to test if the NAT Network works, I'll use the Windows 7 machines and another machine (Its an Arch Linux VM without Graphical Interface).

First, with the machines off, we have to create the NAT Virtual Network: Open VirtualBox and open the `Preferences` dialogue, then go to `Network` and click in `Add new NAT network`.

![](/img/vms/2022-01-31-16-39-56.png)

Then, a Virtual NAT Network will be created. Make sure the left Box is checked. Right click on it and press in `Edit NAT metwork.`

![](/img/vms/2022-01-31-16-42-43.png)

Unless you're an experienced user, make sure the settings are the same as the image. Also, change the network name to another one, so, if not, the network couldn't work properly.

![](/img/vms/2022-01-31-16-48-15.png)

Press OK and close the `Preferences` dialogue. Then open the VM settings, go `Network` and select the `NAT Network` attach mode and make sure to select the Network created before (the name will apprear in the `Name:` list).

![](/img/vms/2022-01-31-16-53-28.png)

> I did it on the both VMs: the Windows and the Linux ones.

Once done, we can turn on the Machines... Once all is up, we can get our Addresses with:

- Windows: `ipconfig` or `ipconfig /all` if we want more information
- Linux: `ifconfig`

![](/img/vms/2022-01-31-17-09-17.png)

As we can see in the image, the Windows IP is `10.0.2.4` and the Linux IP is `10.0.2.15`. Let's see if we have internet access:

![](/img/vms/2022-01-31-17-15-30.png)

We have internet access (ping with `google.com`). Let's also see if we can ping the Linux machine from the Windows Machine and viceversa.

> In order to see if the packets are being received to the Linux machine and sent back to the Windows machine, i'll use the command `tcpdump icmp` to display all the ICMP traffic (The protocol used by the `ping` command).

![](/img/vms/2022-01-31-17-25-10.png)

As we can see, the comunication between the two machines works!

This is a graphical representation of this network mode:

> The virtual DHCP service will give the IP addresses to each Virtual Machines randomly (based on the IP range configured).

![](/img/vms/2022-01-31-17-38-14.png)

----

<p align="center">Thanks for reading! <p>
