# exBOMBER
### A linux server hack/exploit-finder suite

#### Launches choice hack/exploit scanner in detached subshell
- Currently available scanners

:ballot_box_with_check: findbot.pl
:ballot_box_with_check: findcrack0r.pl :new:
:ballot_box_with_check: maldet

- In development

:soon: PHPSiteScan

- Features

:ballot_box_with_check: Emails results
:ballot_box_with_check: Provides pastebin of results
:ballot_box_with_check: Provides scan logfile for 'tail -f'

---

### Watch exBOMBER in action:

 :cinema: http://teeny.ml/exbomber


#### To use:

(root access required)

```
mkdir -p /root/support/exBOMBER
wget https://raw.githubusercontent.com/InterGenStudios/exBOMBER/master/exBOMBER -P /root/support/exBOMBER/ --no-check-certificate
chmod +x /root/support/exBOMBER/exBOMBER
cd /root/support/exBOMBER/ && ./exBOMBER
```
