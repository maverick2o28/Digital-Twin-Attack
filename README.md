# Digital Twin SOC Simulation
### 

A full-stack IT security lab project simulating **digital twin** network attack and defense scenarios with real-time web UI, live log streaming, physical hardware indicators on a Raspberry Pi 2W, and persistent MongoDB logging.

## Table of Contents

1. [Abstract](#abstract)
2. [Project Structure](#project-structure)
3. [Hardware: Raspberry Pi 2W Wiring](#hardware-raspberry-pi-2w-wiring)
   - [Components Needed](#components-needed)
   - [GPIO Pinout](#gpio-pinout-bcm-numbering)
   - [LED State Meanings](#led-state-meanings)
   - [Buzzer Alert Patterns](#buzzer-alert-patterns)
4. [Setup & Run](#setup--run)
   - [1. Clone and Install Dependencies](#1-clone-and-install-dependencies)
   - [2. Run the Server](#2-run-the-server)
   - [3. Test GPIO Hardware](#3-test-gpio-hardware-alone)
   - [4. Run Standalone Attack Scripts](#4-run-standalone-attack-scripts-cli)
5. [Web Dashboard Features](#web-dashboard-features)
6. [Attack Types Simulated](#attack-types-simulated)
7. [IDS/IPS Defense Rules](#idsips-defense-rules)
8. [MongoDB Database](#mongodb-database)
   - [Collections](#collections)
   - [REST API Endpoints](#rest-api-endpoints)
9. [Two-RPi Lab Setup](#two-rpi-lab-setup-offensive--defensive)
10. [Customization](#customization)
11. [Technologies Used](#technologies-used)
12. [Troubleshooting](#troubleshooting)


## Abstract

This project demonstrates the use of a **digital twin** as a real-time replica of a physical system within a simulated small business environment. A Raspberry Pi Zero 2W functions as an edge IoT device by transmitting data to a centralized dashboard that visualizes a network of virtualized office servers and services.

The project further explores how cyberattacks targeting IoT devices and data flows can manipulate the digital twin, resulting in inaccurate system representations and potential real-world consequences. This simulation highlights key challenges at the intersection of IoT, cybersecurity, and digital twin technology — with a focus on both vulnerabilities and defensive strategies.

All network events, attack sessions, IDS alerts, and blocked IPs are persisted in a local **MongoDB** database and viewable through the built-in DB Explorer panel in the web dashboard.


## Project Structure

```

```

