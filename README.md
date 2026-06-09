# Digital Twin SOC Simulation

## Background

As cybersecurity and IT students, we need a safe way to practice detecting and responding to cyberattacks without putting real systems at risk. However, many university programs and corporate training environments rely on outdated simulation tools or isolated lab setups that do not accurately reflect the complexity of real-world networks. Because of this, students often graduate without gaining hands-on experience in observing how attackers behave within a live network environment.

To help address this gap, I am developing a digital twin attack simulation environment. A digital twin is a virtual copy of a real network. In my project, it represents a small business network that includes a web server, a database server, a domain controller, and an edge device, all running inside Docker containers.

The goal of this project is to provide students and researchers with a safe, realistic, and repeatable environment where they can practice using tools such as Nmap and Scapy against real services while monitoring and analyzing the resulting activity with Suricata. This allows users to gain practical experience with both attack simulation and defensive monitoring in a setting that closely resembles a real network.

