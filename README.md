# Knock-Knock: Watch the Bots Try to Break In!

[![Live Demo](https://img.shields.io/badge/LIVE-DEMO-brightgreen?style=for-the-badge)](https://knock-knock.net)

**Live demo:** https://knock-knock.net

_**Watch** the bots knocking on an exposed SSH port on this live, information-packed dashboard! **Discover** the most frequent countries of origin! **Be shocked** by the most common usernames and passwords! **Scoff at and ridicule** the worst offending ISPs and IPs! **Find out** why the bots are choosing these usernames and passwords! **Marvel** at the spinning globe visualizations! Wait, is one of those globes a heat map too - how is that even possible? **View** current break-in attempts and fascinating historic stats, in a series of dynamic, informative, and engaging panels!_

Check it out at https://knock-knock.net, or install it on your own server with an exposed SSH (22) port. Don't worry, these bots may be knocking, but they can't come in!

## Screenshots

**Desktop**

<p align="center">
  <img src="pix/DesktopView.jpg" alt="Knock-Knock desktop dashboard" width="900" />
</p>

**Mobile (carousel panes)**

<p align="center">
  <img src="pix/Mobile_Feed.PNG" alt="Mobile feed" width="210" />
  <img src="pix/Mobile_Globe.PNG" alt="Mobile globe" width="210" />
  <img src="pix/Mobile_Loc.PNG" alt="Mobile locations" width="210" />
</p>
<p align="center">
  <img src="pix/Mobile_User.PNG" alt="Mobile usernames" width="210" />
  <img src="pix/Mobile_Passwd.PNG" alt="Mobile passwords" width="210" />
  <img src="pix/Mobile_Trivia.PNG" alt="Mobile trivia" width="210" />
</p>

## Features

- **Live Feed:** a realtime feed of bots trying to log in to port 22 (knocks). Includes the location, username, password, ISP, and IP
- **Globe View:** a 3D globe showing the location of the last knock. Six different globe styles are available, including a cool extruded country heat map of worst offenders
- **Location:** the countries with the highest knock counts
- **Username:** the most popular usernames tried by the bots
- **Password:** the most common passwords attempted
- **ISP:** the ISP Wall of Shame
- **IP:** the worst offending IP addresses
- **Stats:** statistics on the country, user, password, ISP, and IP of the last knock
- **Trivia:** learn why a username or password may have been chosen
- **Jokes:** some very bad knock-knock jokes

## How It Works

- Listens on the SSH port (22) and captures every unauthorized login attempt
- Enriches attacker IPs with GeoIP (city, country, ISP, ASN)
- Streams live events to the dashboard via WebSockets
- Maintains leaderboards and stats (top countries, users, passwords, ISPs)
- Works well on desktop and mobile with a swipeable carousel

## Installation

Knock-Knock supports three different installation methods, with docker being the simplest. Full instructions live in [INSTALL.md](INSTALL.md).

- **Docker (simplest and universal)**
- **Ubuntu/Debian without Docker**
- **RHEL/CentOS/Fedora without Docker**

## Architecture (In One Breath)

```
SSH Attacker
  ↓
honeypot.py (port 22)
  ↓
monitor.py (GeoIP lookup)
  ↓
SQLite + Redis pub/sub
  ↓
main.py (FastAPI)
  ↓
WebSocket
  ↓
Live Dashboard
```

## License

MIT
