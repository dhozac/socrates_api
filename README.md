# Socrates

## What is Socrates?

Socrates is a datacenter inventory management system built as a
Django app. It keeps track of hardware, virtual machines, networks,
load balancers, and firewalls, including creating them, changing
them, and deleting them. This is done by exposing a number of REST
endpoints, and running a number of Ansible playbooks in response.

## What hardware is supported?

Dell hardware has the best support, including getting warranty
information from their API on a regular basis. HPe hardware has been
thoroughly tested as well. This project is the API, which doesn't
actually care about the hardware specifically, it just keeps track
of it. As long as it has IPMI support, it should work fine.

## What virtualization platforms are supported?

VMware and KVM have received the most thorough testing. oVirt is
mostly there, but is lacking some features at the moment, and hasn't
been tested recently.

## What networks are supported?

The networking code is just using Ansible playbooks, so anything that
you can talk to through Ansible would be supported. Juniper QFabric,
Juniper EX*, Cisco NX-OS, and Cisco ACI have been tested to work
well for switching infrastructures. Fortigate has been tested for
firewalling.
