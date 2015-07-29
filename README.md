# exBOMBER

## Launches choice hack/exploit scanner in a detached subshell, and emails a pastebin of the results


#### Currently available scanners

:white_check_mark:  findbot.pl

:white_check_mark:  findcrack0r.pl  <---:new:

:white_check_mark:  maldet


#### In development

:soon: PHPSiteScan


#### Features

:white_check_mark:  Emails results

:white_check_mark:  Provides pastebin of results

:white_check_mark:  Provides scan logfile for 'tail -f'

---

### Watch exBOMBER in action:

 :cinema: http://teeny.ml/exbomber


#### To use:

(root access required)

```
mkdir -p /root/support/exBOMBER
wget https://raw.githubusercontent.com/InterGenStudios/exBOMBER/master/exBOMBER \
-P /root/support/exBOMBER/ --no-check-certificate
chmod +x /root/support/exBOMBER/exBOMBER
cd /root/support/exBOMBER/ && ./exBOMBER
```
