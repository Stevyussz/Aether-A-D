❯ Downloads
❯ ssh rsctf-ad-game2.key
ssh: Could not resolve hostname rsctf-ad-game2.key: Name or service not known
❯ ssh -i rsctf-ad-game2.key root@10.2.4.4:80
ssh: Could not resolve hostname 10.2.4.4:80: Name or service not known
❯ ssh -i rsctf-ad-game2.key root@10.2.4.4 80
The authenticity of host '10.2.4.4 (10.2.4.4)' can't be established.
ED25519 key fingerprint is SHA256:9Zp8JoWC9ukTgapAEsAnkdVJwk0xoQmO5JWXycA4OLQ.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? ^C
❯ ssh -i rsctf-ad-game2.key root@10.2.4.4
The authenticity of host '10.2.4.4 (10.2.4.4)' can't be established.
ED25519 key fingerprint is SHA256:9Zp8JoWC9ukTgapAEsAnkdVJwk0xoQmO5JWXycA4OLQ.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.2.4.4' (ED25519) to the list of known hosts.
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0664 for 'rsctf-ad-game2.key' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "rsctf-ad-game2.key": bad permissions
root@10.2.4.4: Permission denied (publickey).
❯ ssh -i rsctf-ad-game2.key root@10.2.4.4
❯ chmod 400 rsctf-ad-game2.key
❯ ssh -i rsctf-ad-game2.key root@10.2.4.4
Linux t4-c3 6.12.116+deb13-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.116-1 (2026-11-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Nov 12 20:39:52 2026 from 192.168.95.25
root@t4-c3:~# ls
flag.txt  root.txt
root@t4-c3:~# ls
flag.txt  root.txt
root@t4-c3:~# ls ../
bin   dev  home        initrd.img.old  lib64	  media  opt	root  sbin  sys  usr  vmlinuz
boot  etc  initrd.img  lib	      lost+found  mnt	 proc	run   srv   tmp  var  vmlinuz.old
root@t4-c3:~# cd home
-bash: cd: home: No such file or directory
root@t4-c3:~# ls
flag.txt  root.txt
root@t4-c3:~# cd /var/www/html
root@t4-c3:/var/www/html# ls
assets	footer.php  health.php	index.php  navbar.php  pages  proof.php
root@t4-c3:/var/www/html# 

------

dan ini yg kutemukan di web submitnya: Attack & Defense — Toolkit
Everything you need to play A&D: your personal API token, your VPN config, the API contract, and the rules. The first two sections are actionable — token rotation and VPN config download.


Your API token

A personal Bearer token scoped to you + this game. Your exploit scripts pass it as Authorization: Bearer <token> when submitting captured flags. Every team member manages their own — rotating yours does not affect anyone else, and if you get kicked from the team your token stops working immediately.

Your current token:

ad_ht8s…2TWA

Last used: never

Saved token:

ad_ht8s••••••2TWA
Kept only in this page session for your command examples. It is cleared on reload, logout, or account/game changes. “Rotate” invalidates the previous token; “Forget” clears this copy now.


VPN config

Per-user WireGuard config. The first download generates a fresh keypair + assigns you an IP from the game subnet; subsequent downloads return the same file. Drop the .conf into wg-quick (or wireguard-tools / the WireGuard app) to join the A&D network.

Linux: sudo wg-quick up ./ad-game-….conf. macOS / Windows: import via the official WireGuard app.


Shell access (SSH)

Direct shell into your team's container for any A&D challenge — patch the binary, tail logs, read /flag, install tools. Auth is your SSH key, identity is the SSH username (= the challenge id).

Your registered key:

SHA256:QsOW09OAXobXPc1sGviMESnkM+iFc4tPeZo/H7NkXy8

(ssh-ed25519, platform-generated)

Less secure (the private key crosses the network once). Useful if you don't have ssh-keygen locally, e.g. on Windows without WSL. Downloads a .key file you save and pass to ssh -i.

Connect

ssh <challenge-id>@host -p 22022 -i ~/.ssh/your-key
Replace <challenge-id> with the numeric id from the challenge card (visible in the URL and the "SSH access" hint inside each challenge). The username doubles as the target selector — `ssh 76@host` lands in your team's container for challenge 76.


Rounds & flags

A round (tick) is the scoring unit. Length is set per game — every A&D service shares one tick (the operator picks it, typically 60–180s).
At each tick the platform writes a fresh flag into your container (the "current flag"). You can see it in the challenge modal — protect it.
Old flags stay valid for N ticks (default 5). After that they expire and cannot be accepted as scoring evidence.
Round 0 is warmup — no scoring yet, just make sure your service is up.

How scoring works

The official scoreboard settles accepted outcomes per service inside equal-budget epochs:

Attack: A = min(1, C + 0.25H) C is your accepted-capture coverage over the frozen opponent roster. H adds a bounded capturer-count rarity fraction. An accepted submission records evidence immediately, but it has no standalone point value; the epoch settles all outcomes together.
Defense: D = protected pairs / eligible pairs. Every exact healthy custom-check flag creates one pair per frozen opponent. Each distinct capturer removes only its own protected pair. An unstolen pair is observable non-capture, not proof that an exploit was attempted.
SLA: R = checker credit / service ticks. A clean passing check earns 1.0, recovery earns 0.5, and a failed or missing check earns 0. InternalError carries the last scored non-infrastructure result after startRound. An isolated first error earns 0; only an all-service first-error outage voids the challenge-round sample for the full roster.
Service = 100 × R × (0.40A + 0.40D + 0.20√(A×D)); normalized service weights form the epoch score, and finalized epochs determine official rank.


Find your targets

A&D is attack-first — you need to know every other team's container IP per service. This endpoint is the canonical list. Excludes your own team and waits until the warmup round has elapsed (currentRound > 0).

List request

curl -sS https://finals.tccpens.id/api/Game/2/Ad/Targets \
  -H "Authorization: Bearer ad_ht8sgnGj7740DwBWOAtnm6Q3J__jsyfKY2LZolh2TWA"
Poll once per round (~tickSeconds). Container IPs are stable across rounds unless a team Resets or an admin Stops the container — then a fresh IP shows up here within ~15s.

Response shape

{
  "currentRound": 7,
  "challenges": [
    {
      "challengeId": 76,
      "title": "Test A&D — nginx",
      "tickSeconds": 60,
      "teams": [
        { "participationId": 2, "teamName": "Team Bravo",
          "division": null, "ip": "172.0.9.4", "port": 80,
          "lastCheckStatus": "Ok" },
        { "participationId": 3, "teamName": "Team Charlie",
          "division": null, "ip": "172.0.9.5", "port": 80,
          "lastCheckStatus": "Mumble" }
      ]
    }
  ]
}
lastCheckStatus tells you which targets are healthy: Ok / Mumble / Offline. Prioritize Ok ones — Offline containers won't accept your exploit, and Mumble usually means the service is broken in a way that won't expose the flag.


How to submit captured flags

Flag submission is API-only — there is no web form for A&D. Your exploit scripts batch the flags they collected and POST them in one request.

Submit request

curl -X POST https://finals.tccpens.id/api/Game/2/Ad/Submit \
  -H "Authorization: Bearer ad_ht8sgnGj7740DwBWOAtnm6Q3J__jsyfKY2LZolh2TWA" \
  -H "Content-Type: application/json" \
  -d '{"flags":["flag{captured_from_team_b}","flag{another}"]}'
Pass 1 to 100 flag strings per request. Results return in input order so you can correlate.

Response shape

{
  "acceptedCount": 1,
  "results": [
    { "flag": "flag{captured_from_team_b}",
      "status": "accepted",
      "flagPlantedAtRound": 7 },
    { "flag": "flag{another}",
      "status": "wrong",
      "message": "flag not recognized" }
  ]
}
Per-flag status is one of: accepted | duplicate | wrong | expired | self_attack | not_started. Accepted flags become epoch evidence; the submit response does not assign immediate points.


Your container

The challenge modal shows your container IP:port — that's where checks run and where attackers point their exploits.
The live flag is rewritten every round at the path in the RSCTF_FLAG_FILE environment variable. Read it fresh from $RSCTF_FLAG_FILE on every request (don't cache it).
Never hard-code a platform-specific path. A creation-time RSCTF_FLAG compatibility value may exist, but it becomes stale after rotation — always read $RSCTF_FLAG_FILE.
Patch your service live inside the container — the platform does not redeploy on its own. Your changes live ONLY in the running container; there is no persistent disk.
Your service runs under a supervisor (PID 1). If the service process crashes — or you restart it — it comes back automatically and your patches stay. Restarting the service is safe; but don't kill PID 1 (the supervisor): that drops the box back to the base image.
Reset rebuilds the box from the original image — it WIPES all your changes (patches included), costs SLA during the rebuild, and has a cooldown. Use it only if your box is wedged or compromised, then re-apply your patches.

Do / Don't

Do

Patch your service before the first attack lands.
Automate flag submission — paste into a loop that fetches the current flag from each target and POSTs the batch.
Watch your check status badge — if it goes Mumble/Offline you are losing SLA every tick.
Re-apply your patches after any reset — a reset reverts to the pristine, vulnerable image.
Don't

Share your flags or your token with other teams — operators detect it and apply penalties.
DoS another team's service or the checker infrastructure — instant DQ.
Patch in a way that breaks the legit check (returns 500 to the checker) — you lose SLA equivalent to being offline.
Hard-code the path or cache the flag — read $RSCTF_FLAG_FILE fresh each request, or you'll serve a stale flag and fail the check.
Kill PID 1 (the supervisor) in your box — it resets you to the base image and wipes your patches.
Endpoint base: https://finals.tccpens.id/api/Game/2/Ad



-----

dan pas ku attack ya pake sweep gini terus sama gadaa temuan sama sekali astagaa kayak ga guna gitu attacknya: 

attack control
Sweep menjalankan seluruh arsenal (external tools + recon + auto-login + baca flag di server). Scope-enforced. Flag masuk inbox sebagai PENDING — kamu yang submit di portal.

 pakai external tools (nmap/rustscan/gobuster/ffuf/whatweb) — lebih lengkap, agak lebih lama  + nuclei (CVE checks — lebih lambat, hasil jadi lead)
▶ Sweep SEMUA Lawan (All Targets & Ports)
Switch Auto-Attack Loop: ON (AKTIF)
name	host:ports	kind	owner	actions
opponent-web-PLACEHOLDER	10.2.10.4:80	web	opponent	Sweep :80
our-web-PLACEHOLDER	10.2.4.4:80	web	self	self (defended)
live sweep · done
swept 10.2.10.4: 17 module(s), 0 confirmed, 0 flag(s)
round 7 · confirmed 0 · flags 0
round 7: ▶ sweep 10.2.10.4:80 (recon + login + arsenal)
• recon: crawling the target…
• recon: 4 endpoint(s), 1 param(s)
• login: attempting authentication…
• login: no credentials worked
• arsenal: 17 module(s) to run
✓ done — swept 10.2.10.4: 17 module(s), 0 confirmed, 0 flag(s) → check the Flags tab (PENDING; you submit)
OAST — out-of-band callback (konfirmasi blind SSRF/RCE/XXE)
Listener self-hosted (data callback mendarat di box kita, bukan server publik). Start listener, mint URL unik, suntik ke payload blind; kalau target ping balik = vuln terkonfirmasi (sering bawa data exfil di path/body).

listen port 
80
pub host (IP tim kita) 
10.2.10.4
Start
Stop
Mint URL
Refresh
⚠ PermissionError: [Errno 13] Permission denied
⚠ start the OAST listener first
belum ada interaksi.

---

dan dibagian defense juga gini terus dan aku gatau ini benran udh konek sama punya kita apa belum dan apakah beneran ngelindungin server kita apa ga, dan pas aku klik self-audit source nya ga ada sama sekali respond hadehh, sama sekali coba lihat:
defense control — jaga service kita, jangan sampai kebobolan
Deteksi web shell & perubahan file di service sendiri, lalu bersihkan dengan aman (backup dulu, reversible). Service tetap harus UP (dicek juri/SLA).

Jalankan defense sweep
Self-audit source (patch diri dulu)
Jalankan AutoGuard 1x
Scan ulang web shell
Shield proxy dihentikan
perisai file (AutoGuard — self-healing & karantina)
Otomatis karantina file asing & pulihkan file inti dari snapshot setiap siklus.

Switch AutoGuard: ON (AKTIF)
cycles: 27 · quarantined: 0 · restored: 0
perisai jaringan (HTTP Shield Proxy — filter input)
Reverse-proxy di depan port web kita dengan saklar ON/OFF instan.

listen port 
8080
backend port 
8000
Start Proxy
Stop
SLA allow IP (checker juri, pisah koma) 
10.60.0.1
allow path 
/healthz,/sla
Set allowlist
Filter Switch: ON (BLOCKING)
● stopped · req: 0 · blocked: 0
SLA-safe: IP/path di allowlist tidak akan pernah diblok → service tetap lolos cek juri walau filter ON.

traffic capture — exploit musuh (curi & replay ala Tulip)
Setiap request musuh yang masuk ke Shield kita direkam. Yang terdeteksi sebagai serangan bisa di-replay ke semua tim lawan (scope-enforced) — curi exploit mereka, balikin ke mereka. Flag hasil replay masuk inbox PENDING.

Refresh capture
total: 0 · serangan: 0 · buffer: 0
belum ada serangan tertangkap.
self-audit — sink yang bisa di-exploit lawan (patch SEBELUM kebobolan)
Cerminan arsenal attack ke dalam: LFI/cmdi/SSTI/SQLi/upload/file ke-expose di source service kita, lengkap dengan saran patch. Read-only.

✓ tidak ada sink mencolok. Tetap cek manual.
0
web shell
0
incident CRITICAL
0/0
service UP
0
file integrity drift
web shell terdeteksi — klik Quarantine untuk membersihkan
bersih — tidak ada web shell di watched roots
incidents
tidak ada incident
file integrity — service kita
belum ada path yang dipantau (set owner=self + notes di Config)
services — status & functional check (SLA)
no service probes
log modifikasi / patch (semua reversible)
