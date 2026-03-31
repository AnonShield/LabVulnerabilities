# Security Audit Report: VulnLab Scanner
**Version**: 1.0.0
**Date**: 2026-03-30
**Auditor**: Principal Security Engineer & System Architect

## 1. Executive Summary
This report details the security architecture and potential risks associated with the VulnLab Scanner, specifically regarding the execution of untrusted Docker images for vulnerability scanning. The system implements a robust "Defense-in-Depth" strategy, but inherent risks of container escapes remain when dealing with malicious images.

## 2. Threat Model
### 2.1. Actors
- **The Scanner (Trusted)**: Orchestrates the environment.
- **OpenVAS (Trusted)**: Performs the network-level scan.
- **Target Container (Untrusted)**: Arbitrary image from DockerHub.

### 2.2. Attack Vectors
- **Host Escape**: Malicious image exploiting Docker engine vulnerabilities to gain Host access.
- **Lateral Movement**: Scanned container attacking the OpenVAS instance or other containers on the same bridge.
- **Resource Exhaustion (DoS)**: Container consuming all CPU/RAM/Disk of the host.
- **Data Exfiltration**: Container attempting to send host data to external C2 servers.

## 3. Implemented Mitigations (Vistoria Técnica)

### 3.1. Container Hardening (Layer 1)
In `scanner/mass_scan/container.py`, the following security flags are enforced:
- **`cap_drop=["ALL"]`**: Removes all Linux capabilities. This is the single most effective mitigation against traditional exploits.
- **`security_opt=["no-new-privileges:true"]`**: Prevents the container from gaining new privileges via SUID binaries.
- **`read_only=True`**: Mounts the container's root filesystem as read-only.
- **`tmpfs`**: Provides minimal, non-executable writable areas for applications that require it.
- **`mem_limit="512m"`**: Hard memory limit.
- **`nano_cpus=1000000000`**: Limits the container to 1 CPU core.
- **`pids_limit=256`**: Prevents fork-bomb attacks.

### 3.2. Network Isolation (Layer 2)
In `scanner/mass_scan/setup.py`:
- **Dedicated Bridge**: Containers are placed in `trabalho_vulnnet`.
- **No Port Mapping**: Scanned containers have NO exposed ports to the host network.
- **Control Plane Isolation**: The OpenVAS GMP API (port 9390) is bound to `127.0.0.1` on the host, making it unreachable for the scanned containers.

### 3.3. Control Plane Hardening (Layer 3)
- **Credential Management**: GVM passwords are not hardcoded in logs and are passed via environment variables.
- **API Access**: The Python orchestrator communicates with GVM over an encrypted TLS connection (localhost).

## 4. Identified Risks & Recommendations

### 4.1. [HIGH] Container Escape via Kernel Vulnerabilities
**Observation**: While `cap-drop` is effective, it doesn't protect against direct Kernel exploits.
**Recommendation**: Use a specialized runtime like **gVisor (runsc)** or **Kata Containers** for the scanned containers. This adds a second kernel/sandbox layer.

### 4.2. [MEDIUM] Lateral Movement on Bridge
**Observation**: `com.docker.network.bridge.enable_icc` is set to `true`. This allows containers on the same network to communicate. While necessary for OpenVAS to scan the target, it also allows a target to attack OpenVAS.
**Recommendation**: Implement Docker network aliases or specific IPtables rules to ensure only the OpenVAS container can initiate connections to the target containers.

### 4.3. [MEDIUM] Disk Space Exhaustion
**Observation**: Pulling thousands of images can fill the host disk.
**Recommendation**: The current `remove_image_after: true` is good, but a `docker system prune` should be triggered automatically if disk usage exceeds 85%.

## 5. Conclusion
The VulnLab Scanner architecture is significantly more secure than standard automation scripts. By applying "Default Deny" principles at the capability and network levels, the blast radius of a compromised image is minimized. However, for a production environment scanning high-risk images, upgrading the runtime to a micro-VM based solution (Kata) or a process-level sandbox (gVisor) is strongly advised.

---
*End of Report*
