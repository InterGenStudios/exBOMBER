# exBOMBER
### A linux server hack/exploit-finder suite

- Launches choice hack/exploit scanner in detached subshell
    - findbot.pl        - Working
    - findcrack0r.pl    - Working
    - maldet            - Working
    - PHPSiteScan       - In development
- Emails results                      - Working
- Provides pastebin of results        - Working
- Provides scan logfile for 'tail -f' - Working

---

### Watch exBOMBER in action:

 ===> http://teeny.ml/exbomber


#### To use:

(root access required)

```
mkdir -p /root/support/exBOMBER
wget https://raw.githubusercontent.com/InterGenStudios/exBOMBER/master/exBOMBER -P /root/support/exBOMBER/ --no-check-certificate
chmod +x /root/support/exBOMBER/exBOMBER
cd /root/support/exBOMBER/ && ./exBOMBER
```
