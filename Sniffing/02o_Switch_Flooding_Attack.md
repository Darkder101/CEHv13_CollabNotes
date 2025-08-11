## what is Switch ? 
First, what a switch normally does A network switch is like a super-organized post office for data inside a network.
It has a MAC address table (think of it as a delivery list) that tells it:
- "MAC address X is connected to port 3"
- "MAC address Y is connected to port 5"
- This means it sends each data packet only to the correct destination — not to every device.

## The attack
- A switch flooding attack happens when an attacker deliberately overwhelms the switch’s MAC address table by sending a huge number of fake MAC addresses into it.
- The attacker’s computer sends packets with thousands of different, made-up MAC addresses.
- The switch tries to store them all, but its table has a limited size.
- Once the table is full, the switch forgets the real addresses.
  
## The result
When the table is full, the switch doesn’t know which device is where anymore.So instead of sending data only to the intended device, it starts broadcasting traffic to all devices — like a hub.

This means:
- The attacker can now see (sniff) data meant for other devices.
- It’s a stepping stone for packet sniffing or man-in-the-middle attacks.
