# 🛡️ Mitigation of DoS Attacks in Software-Defined Networking using Ryu Controller and Mininet

This project presents a practical solution to detect and mitigate **Denial of Service (DoS)** attacks in **Software-Defined Networking (SDN)** using the **Ryu Controller** and **Mininet**. The system includes a real-time Web UI built with **Next.js**, and integrates with **Prometheus** and **Grafana** for network monitoring and alerting.

> 🔗 Related Repository: [Frontend Web UI - sdn_dashboard](https://github.com/VietDucc/sdn_dashboard)

> **Keywords:** SDN, Ryu Controller, DoS Attack, Mininet, Network Security, Next.js, Grafana, Prometheus

---

## 📌 Abstract
This project explains and implements a method to detect and prevent DoS attacks within SDN environments. We leverage the Ryu controller to monitor traffic, Mininet for topology simulation, and Prometheus + Grafana for real-time visualization.

Since **Ryu does not provide a built-in user interface**, we also developed a **custom Web-based dashboard** at [sdn_dashboard](https://github.com/VietDucc/sdn_dashboard).  
> 🖥️ This dashboard enables administrators to **monitor and respond to threats promptly, even from mobile or remote devices**—as long as there's an internet connection.

---

## 🏗️ System Architecture

- **Mininet**: Emulates a layered topology with switches and hosts
- **Ryu**: Manages OpenFlow switches, tracks port throughput, and blocks abnormal traffic
- **Prometheus**: Collects metrics from Ryu
- **Grafana**: Visualizes real-time metrics (RX, TX, thresholds, etc.)
- **Web UI (Next.js)**: Allows admin login, host/port/IP blocking, threshold adjustment, and real-time visualization

> 🚧 Port-level attack detection based on RX/TX throughput  
> ⚡ Auto-blocks ports exceeding dynamic thresholds  
> 🔓 Auto-unblock after traffic normalizes  
> 🔐 Secure Web UI with domain restrictions and login

---

## 🌐 Web UI Features (📁 [`sdn_dashboard`](https://github.com/VietDucc/sdn_dashboard))

- Admin login (`admin` / `admin`)
- Show hosts, IPs, and switch-port mapping
- Block/unblock by IP or switch port
- View and update dynamic traffic thresholds
- Real-time traffic monitoring
- Access secured by domain whitelisting
- Fully responsive: works on PC, laptop, and mobile devices

---

## 🧠 Attack Detection Logic

- Traffic monitored using `EventOFPPortStatsReply`
- Throughput = ΔBytes / ΔTime
- Each port’s threshold = 80% of its link bandwidth (from `link_bandwidth.json`)
- Abnormal if sustained traffic > threshold for 5 seconds → auto block
- Auto unblock after 10 seconds of normal traffic
- Repeat attackers are permanently blocked

---

## 📊 Monitoring & Visualization

- Prometheus scrapes metrics from Ryu (via custom API)
- Grafana dashboards show:
  - Host connections
  - Per-port throughput
  - Switch performance
  - Packet stats and bandwidth

---

## ✅ Test Results

- Simulated DoS with `ping -f -s 65500`
- Auto-detection, block after 5s, unblock after 10s
- Permanent block on repeated attacks
- Verified control through Web UI and CLI
- Grafana showed real-time traffic spikes and port states

---

## 🔮 Future Work

1. **Infrastructure as Code (IaC)**: Use Terraform to auto-deploy Mininet, Ryu, Prometheus, and Grafana
2. **CI/CD Pipeline**: GitHub Actions + Docker + Ansible for automation and security scanning (ESLint, SonarQube, Trivy, etc.)
3. **Web Security Enhancements**:
   - Use OAuth2 / JWT for authentication
   - Session tracking
   - Alerts via Email / Telegram
   - Historical tracking of blocked/unblocked ports
4. **ML-based Detection**:
   - Train models to detect anomalies dynamically
   - Adaptive thresholds based on day/week patterns

---

## 📚 References

- [Ryu SimpleSwitch13 Source Code](https://github.com/faucetsdn/ryu/blob/master/ryu/app/simple_switch_13.py)
- [The Ryu Book](https://book.ryu-sdn.org/en/Ryubook.pdf)
- [Mininet](http://mininet.org/)
- [Open Networking Foundation](https://opennetworking.org/)

---

## 👨‍💻 Authors

- **Project by:** Viết Đức
- **Institution:** University of Information Technology - VNU HCM  
