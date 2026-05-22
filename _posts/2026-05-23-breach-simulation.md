---
layout: post
title: "Breach Simulation using SliverC2"
date: 2026-05-23
author: Fahad
---

# Breach Simulation: Lateral Movement using Sliver C2

This was designed to be tested against a certain security product, I focused on post-exploitation flow using Sliver C2 to demonstrate how initial access can be expanded into internal lateral movement inside a segmented environment. All testing was conducted in a testing active directory environment built especially for this.

---

## Command & Control

After the initial payload execution, the compromised host established a reverse TCP connection back to my external C2 server. From there, We have an interactive session and full control over the endpoint.

![](https://raw.githubusercontent.com/quantumcore/quantumcore.github.io/refs/heads/master/assets/images/untitled-3_20260106192613371.png)

---

## Credential Access

Once I had a stable session, I moved into credential harvesting. I used Mimikatz to extract NTLM hashes and Kerberos tickets directly from LSASS.

![](https://raw.githubusercontent.com/quantumcore/quantumcore.github.io/refs/heads/master/assets/images/untitled-3_20260106192657651.png)

---

## Pivoting via Tunnel

To reach internal systems that were not directly exposed, I set up a Chisel tunnel from my attack machine.

Server was running externally

![](https://raw.githubusercontent.com/quantumcore/quantumcore.github.io/refs/heads/master/assets/images/untitled-3_20260106192830952.png)

On the compromised host (`socenv`), I ran the Chisel client to create a reverse SOCKS5 tunnel back through the C2 channel. This effectively places my tooling inside the internal network.

![](https://raw.githubusercontent.com/quantumcore/quantumcore.github.io/refs/heads/master/assets/images/untitled-3_20260106192806563.png)

---

## Internal Reconnaissance

Through the tunnel, I ran internal discovery using `netexec`. The focus was on identifying live hosts, open SMB services, and reachable systems across the subnet.

Mapping potential lateral movement targets, Going further into the network.

![](https://raw.githubusercontent.com/quantumcore/quantumcore.github.io/refs/heads/master/assets/images/untitled-3_20260106193323747.png)

---

## Lateral Movement

With valid domain credentials already extracted, I targeted an internal system at `10.2.13.214`.

Using `netexec` authenticated over SMB and executed a remote command to verify access before deploying the payload.

![](https://raw.githubusercontent.com/quantumcore/quantumcore.github.io/refs/heads/master/assets/images/untitled-3_20260106192911511.png)

From there, I delivered the backdoor using a PowerShell download-and-execute.

![](https://raw.githubusercontent.com/quantumcore/quantumcore.github.io/refs/heads/master/assets/images/untitled-3_20260106193018793.png)

---

## Second Foothold

The payload executed successfully on `10.2.13.214`, and a new C2 session was established.

At this point, We have a second independent foothold inside the network, separate from the initial host.

![](https://raw.githubusercontent.com/quantumcore/quantumcore.github.io/refs/heads/master/assets/images/untitled-3_20260106193104626.png)

---

## Credential Expansion

On the newly compromised machine, I repeated credential extraction using Mimikatz.

![](https://raw.githubusercontent.com/quantumcore/quantumcore.github.io/refs/heads/master/assets/images/untitled-3_20260106193152884.png)

---

Successful lateral propagation across the environment.

