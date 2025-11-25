# Before attending Network Interception in Rust: Building a MITM Tool from Scratch

This document describes the necessary actions and setup required to prepare for
the training **Network Interception in Rust: Building a MITM Tool from
Scratch**.


## Supported OS

In order of preference for the training:

- Any modern Linux x86_64.
- Windows 10/11 x86_64 **without** WSL (you can have WSL installed, but you
  should compile and run Rust code without WSL).
- macOS 10.15+ aarch64.

Your host must be able to run and compile Rust code at least version 1.85.1.

## Lab Setup

Following this setup, you will deploy a complete lab on your host that will help
you test the tool you will write during the training.

This setup uses two virtual machines that will act as a legitimate client and
server, and your host machine will be used to run the attack. The network of
this virtual lab is described in the following graph.

Only follow the part dedicated to your operating system, and then confirm that
your setup is working with the [lab setup checklist](#lab-setup-checklist).

- [Linux](#linux)
- [Windows](#windows)
- [macOS](#macos)

### Linux

#### Requirements

- Any modern Linux x86_64.
- A Rust development environment with Rust at least version 1.85.1.
- `libvirt`, `qemu-kvm-x86` (or just `qemu-kvm` depending on your distro) and
  `virt-manager` (tested on version 9.0.0).

Download the two virtualization images from <http://152.53.22.37/workshop/>.

| File                     | Size | sha256sum                                                        |
| ------------------------ | ---- | ---------------------------------------------------------------- |
| `rust-mitm-client.qcow2` | 8.7G | 961374f1be36456468844e4840eda461179b3da04f2553ec7bb7eb634a9c63cb |
| `rust-mitm-server.qcow2` | 8.7G | 50fd05747a88a57f8f734a9d4770f0f690f1372be6dbbb54e0979b10e8881374 |

#### Setting up your host environment

1. Disable IPv4 forwarding on your host
    ```bash
    sudo sysctl -w net.ipv4.ip_forward=0
    ```
2. Clone the GitHub repository:
    ```bash
    git clone https://github.com/LeoniePhiline/mitm_training.git -b workshop
    ```
    You have been invited to the repository for read access.
    All commands running on your host assume that it is the current working
    directory.

#### Setting up the lab

1. Copy the two files `rust-mitm-client.qcow2` and `rust-mitm-server.qcow2` to `/var/lib/libvirt/images`
  (use sudo of copy as root if you have any permission issues).
2. Start `virt-manager`.
3. Go to Edit > Preferences > General and Enable XML editing.
4. Setup network. Select 'QEMU/KVM' then go to Edit > Connection Details > Virtual Networks > `+`.
    1. Name: `rust-mitm`.
    2. Mode: Isolated.
    3. IPv4 Configuration.
        1. Network `192.168.56.0/24`.
        2. Disable DHCPv4.
        3. Finish.
5. Setup server. Select 'QEMU/KVM' then go to File > New Virtual Machine.
    1. Import existing disk image.
    2. Browse > default > select `rust-mitm-server.qcow2` > Choose Volume.
    3. Operating system: Debian 11 or Debian 12 (it does not matter).
    4. Memory: 2048MiB.
    5. CPUs: 2.
    6. Name: `rust-mitm-server`.
    7. Select Customize configuration before installation.
    8. Network selection: Virtual network `rust-mitm`.
    9. Finish.
    10. Go to NIC > XML.
        1. Replace the existing MAC address with `08:00:27:f3:4d:aa`.
        2. Apply. The XML configuration should look like this:
            ```xml
            <interface type="network">
                <mac address="08:00:27:f3:4d:aa"/>
                <source network="rust-mitm"/>
                <model type="virtio"/>
                <address type="pci" domain="0x0000" bus="0x01" slot="0x00" function="0x0"/>
            </interface>
            ```
    11. Click "Begin Installation" and the VM should start.
6. Setup client. Select 'QEMU/KVM' then go to File > New Virtual Machine.
    1. Import existing disk image.
    2. Browse > default > select `rust-mitm-client.qcow2` > Choose Volume.
    3. Operating system: Debian 11 or Debian 12 (it does not matter).
    4. Memory: 2048MiB.
    5. CPUs: 2.
    6. Name: `rust-mitm-client`.
    7. Select Customize configuration before installation.
    8. Network selection: Virtual network `rust-mitm`.
    9. Finish.
    10. Go to NIC > XML.
        1. Replace the existing MAC address with `08:00:27:1f:1b:f3`.
        2. Apply. The XML configuration should look like this:
            ```xml
            <interface type="network">
                <mac address="08:00:27:1f:1b:f3"/>
                <source network="rust-mitm"/>
                <model type="virtio"/>
                <address type="pci" domain="0x0000" bus="0x01" slot="0x00" function="0x0"/>
            </interface>
            ```
    11. Click "Begin Installation" and the VM should start.

#### Running the lab

##### MitM Server

On the _rust-mitm-server_ VM

1. Start the VM.
2. Connect with username `user` and password `changeme`.
    1. Qwerty layout on the graphical interface.
    2. SSH on port 22.

No further action are required once you have connected to the server VM.

##### MitM Attacker

On your _host machine_

1. Build the attacker binary `cargo build`.
2. Run the attacker binary `sudo target/debug/mitm_training`.
3. Run `ip a` and write down the `link/ether` address of the libvirt network
    bridge (e.g., `virbr1`). You will need it for the next part.
    ```bash
    ...
4: virbr1: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 52:54:00:5e:34:87 brd ff:ff:ff:ff:ff:ff
    inet 192.168.56.1/24 brd 192.168.56.255 scope global virbr1
       valid_lft forever preferred_lft foreve
    ...
    ```

##### MitM Client

On the _rust-mitm-client_ VM

1. Start the VM.
2. Connect with username `user` and password `changeme`.
    1. Qwerty layout on the graphical interface.
    2. SSH on port 22.
3. Open `/home/user/config.json` and update the `mitm_mac_address` field with
    the MAC address of the bridge on your host that you wrote down from the
    previous part.
    ```json
    {
        ...
        "mitm_mac_address": "52:54:00:5e:34:87"
        ...
    }
    ```

To test your attacker tool, you can now run
`sudo mitm_client -c config.json` in `/home/user`. The process should stop with
a failed assertion: this is expected as you have not started coding the
MitM program.

### Windows

#### Requirements

- Windows 10/11 x86_64 **without** WSL (you can have WSL installed, but you
  should compile and run Rust code without WSL).
- A Rust development environment with Rust at least version 1.85.1.
- VirtualBox (at least version 7.1.0).
- Npcap installed: https://npcap.com/#download (tested with version 1.83)
- Npcap SDK: https://npcap.com/#download  (tested with SDK version 1.15).
  Extract `/Lib/x64/Packet.lib` at the root of the Rust project.
- (Optional): a SSH client to connect to the VM more easily (see 
  <https://learn.microsoft.com/en-us/windows/terminal/tutorials/ssh>)

Download the two virtualization images from <http://152.53.22.37/workshop/>.

| File                   | Size | sha256sum                                                        |
| ---------------------- | ---- | ---------------------------------------------------------------- |
| `rust-mitm-client.ova` | 3.2G | da574e80a2247f84dd74dbde746ce3fd7cd201556969f4fd33eb2227ab28d8f4 |
| `rust-mitm-server.ova` | 3.2G | e312940fbb1cd0e367a32ca529cba43e5b438f5097570fe6d824bdf0382e7955 |

#### Setting up your host environment

Open a command prompt as **Administrator**

1. Add a static ARP route for the `rust-mitm-server`. If this fails, reboot your
    computer and run the same command **before starting VirtualBox**. This
    command is not persistent across reboots.
    ```powershell
    arp -s 192.168.56.20 08-00-27-f3-4d-aa 192.168.56.1
    ```
2. Pull the GitHub repository. The repository is available at
    <https://github.com/LeoniePhiline/mitm_training>. You will have access
    to the repository once we have invited you to the GitHub organisation. 
    All commands running on your host assume that it is the current working
    directory.

#### Setting up the lab

1. Start VirtualBox.
2. Go to network tab > Host-only Networks > Create (if the network does not exist).
    1. IPv4 Address: `192.168.56.1`.
    2. IPv4 Network Mask: `255.255.255.0`.
    3. DHCP Server: disabled.
3. Setup server.
    1. File > Import Appliance...
    2. Select `rust-mitm-server.ova`.
    3. Settings > Generate new MAC addresses for all network adapters.
    4. Finish.
    5. Right-click the VM > Settings > Network (some config may already be correct).
        1. Enable Adapter 1.
        2. Attached to `Host-only Adapter`.
        3. Name `VirtualBox Host-Only Ethernet Adapter` (the network created in step 2.).
        4. **MAC Address** `080027F34DAA`.
4. Setup client.
    1. File > Import Appliance...
    2. Select `rust-mitm-client.ova`.
    3. Settings > Generate new MAC addresses for all network adapters.
    4. Finish.
    5. Right-click VM > Settings > Network (some config may already be correct).
        1. Enable Adapter 1.
        2. Attached to `Host-only Adapter`.
        3. Name `VirtualBox Host-Only Ethernet Adapter` (the network created in step 2.).
        4. **MAC Address** `0800271F1BF3`.

#### Running the lab

##### MitM Server

On the _rust-mitm-server_ VM

1. Start the VM.

##### MitM Attacker

On your _host machine_

1. Build the attacker binary `cargo build`.
2. Run the attacker binary `cargo run`.
3. Run `ipconfig /all` and write down the Physical Address (`0A-00-27-00-00-33`
    in the example) of the VirtualBox network. You will need it for the next
    part.
    ```
    ...
    Ethernet adapter Ethernet 2:

       Connection-specific DNS Suffix  . :
       Description . . . . . . . . . . . : VirtualBox Host-Only Ethernet Adapter
       Physical Address. . . . . . . . . : 0A-00-27-00-00-33
       DHCP Enabled. . . . . . . . . . . : No
       Autoconfiguration Enabled . . . . : Yes
       Link-local IPv6 Address . . . . . : fe80::59e2:6404:44bc:9e7a%51(Preferred)
       IPv4 Address. . . . . . . . . . . : 192.168.56.1(Preferred)
       Subnet Mask . . . . . . . . . . . : 255.255.255.0
       Default Gateway . . . . . . . . . :
       DHCPv6 IAID . . . . . . . . . . . : 856293415
       DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-30-3D-D5-22-34-73-5A-DB-F2-2F
       DNS Servers . . . . . . . . . . . : fec0:0:0:ffff::1%1
                                           fec0:0:0:ffff::2%1
                                           fec0:0:0:ffff::3%1
       NetBIOS over Tcpip. . . . . . . . : Enabled
    ...
    ```

##### MitM Client

On the _rust-mitm-client_ VM

1. Start the VM.
2. Connect with username `user` and password `changeme`.
    1. Qwerty layout on the graphical interface.
    2. SSH on port 22.
3. Open `/home/user/config.json` and update the `mitm_mac_address` field with
    the MAC address of the bridge on your host that you wrote down from the
    previous part (replace the dashes `-` with colons `:`).
    ```json
    {
        ...
        "mitm_mac_address": "0A:00:27:00:00:33"
        ...
    }
    ```

To test your attacker tool, you can now run
`cargo run -- -c config.json`. The process should stop with a failed assertion:
this is expected as you have not started coding the MitM program.

### macOS

#### Requirements

- macOS 10.15+ aarch64.
- A Rust development environment with Rust at least version 1.85.1.
- UTM (tested on v4.6.5).

Download the two virtualization images from <http://152.53.22.37/workshop/>.

| File                             | Size | sha256sum                                                        |
| -------------------------------- | ---- | ---------------------------------------------------------------- |
| `rust-mitm-client-arm64.utm.tgz` | 3.0G | e2347abdac0df288145b58e3a11800cfd3767f39442f02417cd98dc28ad26669 |
| `rust-mitm-server-arm64.utm.tgz` | 3.0G | c07ca6a050df4823a10d065ddec7ab7e64e7ce51cab873bce7cdce1d97e0b76f |

#### Setting up your host environment

1. Pull the GitHub repository. The repository is available at
    <https://github.com/LeoniePhiline/mitm_training>. You will have access
    to the repository once we have invited you to the GitHub organisation. 
    All commands running on your host assume that it is the current working
    directory.

#### Setting up the lab

1. Extract both VM files.
    ```bash
    tar -xvf rust-mitm-client-arm64.utm.tgz
    tar -xvf rust-mitm-server-arm64.utm.tgz
    ```
2. Import the server VMs in UTM: File > New > Open and select the rust-mitm-server.utm folder.
3. Import the client VMs in UTM: File > New > Open and select the rust-mitm-server.utm folder.

#### Running the lab

##### MitM Server

On the _rust-mitm-server_ VM

1. Start the VM.

##### MitM Attacker

On your _host machine_

1. Build the attacker binary `cargo build`.
2. Run the attacker binary `sudo target/debug/mitm_training`.
3. Run `ifconfig` and write down the ether address (`1a:4a:53:01:37:64` in the
    example) of the UTM bridge. You will need it for the next part.
    ```bash
    ...
    bridge100: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        options=3<RXCSUM,TXCSUM>
        ether 1a:4a:53:01:37:64
        inet 192.168.56.1 netmask 0xffffff00 broadcast 192.168.56.255
        inet6 fe80::184a:53ff:fe01:3764%bridge100 prefixlen 64 scopeid 0x15
        Configuration:
                id 0:0:0:0:0:0 priority 0 hellotime 0 fwddelay 0
                maxage 0 holdcnt 0 proto stp maxaddr 100 timeout 1200
                root id 0:0:0:0:0:0 priority 0 ifcost 0 port 0
                ipfilter disabled flags 0x0
        member: vmenet0 flags=3<LEARNING,DISCOVER>
                ifmaxaddr 0 port 20 priority 0 path cost 0
        nd6 options=201<PERFORMNUD,DAD>
        media: autoselect
        status: active
    ...
    ```

##### MitM Client

On the _rust-mitm-client_ VM

1. Start the VM.
2. Connect with username `user` and password `changeme`.
    1. Qwerty layout on the graphical interface.
    2. SSH on port 22.
3. Open `/home/user/config.json` and update the `mitm_mac_address` field with
    the MAC address of the bridge on your host that you wrote down from the
    previous part.
    ```json
    {
        ...
        "mitm_mac_address": "1a:4a:53:01:37:64"
        ...
    }
    ```

To test your attacker tool, you can now run
`sudo mitm_client -c config.json` in `/home/user`. The process should stop with
a failed assertion: this is expected as you have not started coding the MitM
program.

### Lab setup checklist

- [ ] Building the attacker binary on the host
  - `cargo build`
- [ ] Running the attacker binary on the host
  - **Linux**: `sudo target/debug/mitm_training`
  - **Windows**: `cargo run`
  - **macOS**: `sudo target/debug/mitm_training`
- [ ] Check the network configuration on your host.
  - **Linux**. must match `inet 192.168.56.1/24` with `ip a` command
    ```
    $ ip a
    ...
    3: virbr1: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
        link/ether 52:54:00:e3:40:02 brd ff:ff:ff:ff:ff:ff
        inet 192.168.100.1/24 brd 192.168.100.255 scope global virbr1
        valid_lft forever preferred_lft forever
    ...
    ```
  - **Windows**. must match `IPv4 Address: 192.168.56.1` and `Subnet Mask: 255.255.255.0` with `ipconfig /all` command.
    ```
    $ ipconfig /all
    ...
    Ethernet adapter Ethernet 2:

       Connection-specific DNS Suffix  . :
       Description . . . . . . . . . . . : VirtualBox Host-Only Ethernet Adapter
       Physical Address. . . . . . . . . : 0A-00-27-00-00-33
       DHCP Enabled. . . . . . . . . . . : No
       Autoconfiguration Enabled . . . . : Yes
       Link-local IPv6 Address . . . . . : fe80::59e2:6404:44bc:9e7a%51(Preferred)
       IPv4 Address. . . . . . . . . . . : 192.168.56.1(Preferred)
       Subnet Mask . . . . . . . . . . . : 255.255.255.0
       Default Gateway . . . . . . . . . :
       DHCPv6 IAID . . . . . . . . . . . : 856293415
       DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-30-3D-D5-22-34-73-5A-DB-F2-2F
       DNS Servers . . . . . . . . . . . : fec0:0:0:ffff::1%1
                                           fec0:0:0:ffff::2%1
                                           fec0:0:0:ffff::3%1
       NetBIOS over Tcpip. . . . . . . . : Enabled*
    ...
    ```
  - **macOS**. must match `inet 192.168.56.1 netmask 0xffffff00` with `ifconfig` command.
    ```
    $ ifconfig
    ...
    bridge100: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        options=3<RXCSUM,TXCSUM>
        ether 1a:4a:53:01:37:64
        inet 192.168.56.1 netmask 0xffffff00 broadcast 192.168.56.255
        inet6 fe80::184a:53ff:fe01:3764%bridge100 prefixlen 64 scopeid 0x15
        Configuration:
                id 0:0:0:0:0:0 priority 0 hellotime 0 fwddelay 0
                maxage 0 holdcnt 0 proto stp maxaddr 100 timeout 1200
                root id 0:0:0:0:0:0 priority 0 ifcost 0 port 0
                ipfilter disabled flags 0x0
        member: vmenet0 flags=3<LEARNING,DISCOVER>
                ifmaxaddr 0 port 20 priority 0 path cost 0
        nd6 options=201<PERFORMNUD,DAD>
        media: autoselect
        status: active
    ...
    ```
- [ ] Check the network configuration on the server with `ip a` command.
  - [ ] must match `inet 192.168.56.20/24`
  - [ ] must match `link/ether 08:00:27:f3:4d:aa`
    ```bash
    $ ip a
    ...
    2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
        link/ether 08:00:27:f3:4d:aa brd ff:ff:ff:ff:ff:ff
        inet 192.168.56.20/24 brd 192.168.56.255 scope global noprefixroute enp0s3
            valid_lft forever preferred_lft forever
        inet6 fe80::a00:27ff:fef3:4daa/64 scope link noprefixroute
            valid_lft forever preferred_lft forever
    ...
    ```
- [ ] Check the network configuration on the client with `ip a` command.
  - [ ] must match `inet 192.168.56.10/24`
  - [ ] must match `link/ether 08:00:27:1f:1b:f3`
    ```bash
    $ ip a
    ...
    2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
        link/ether 08:00:27:1f:1b:f3 brd ff:ff:ff:ff:ff:ff
        inet 192.168.56.10/24 brd 192.168.56.255 scope global noprefixroute enp0s3
            valid_lft forever preferred_lft forever
        inet6 fe80::a00:27ff:fe1f:1bf3/64 scope link noprefixroute
            valid_lft forever preferred_lft forever
    ...
    ```
- [ ] Check the connectivity between the server and your host
  ```bash
  # on your host
  ping 192.168.56.20
  ```
- [ ] Check the connectivity between the client and your host
  ```bash
  # on your host
  ping 192.168.56.10
  ```
- [ ] Check the connectivity between the client and the server
  ```bash
  # on the client
  ping 192.168.56.20
  ```
- [ ] Check that the HTTP server is running and accessible from the client
  ```bash
  # on the client
  wget http://192.168.56.20/bytes/128
  ```
