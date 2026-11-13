"""GET-only IOC enrichment. Offline by default, no indicator URLs fetched."""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request

class ProviderError(Exception):
    """Sanitized error; never includes provider response bodies or credentials."""

def normalize(value):
    value=value.strip().replace('[.]','.')
    if not value or len(value)>253 or '%' in value: raise ValueError('empty or oversized IOC')
    try: return 'ip', str(ipaddress.ip_address(value))
    except ValueError: pass
    if re.fullmatch(r'[a-fA-F0-9]{64}',value): return 'sha256',value.lower()
    value=value.lower().rstrip('.')
    labels=value.split('.')
    if (len(labels)>1 and re.fullmatch(r'(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})',labels[-1])
        and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in labels)):
        return 'domain',value
    raise ValueError('expected IP, ASCII domain or SHA-256; URL/email rejected')

def get_json(url,headers):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,req,fp,code,msg,hdrs,newurl): return None
    try:
        opener=urllib.request.build_opener(NoRedirect())
        with opener.open(urllib.request.Request(url,headers=headers,method='GET'),timeout=10) as response:
            body=response.read(1_000_001)
        if len(body)>1_000_000: raise ProviderError('response_too_large')
        return json.loads(body)
    except urllib.error.HTTPError as exc:
        exc.close()
        raise ProviderError({401:'unauthorized',403:'forbidden',404:'not_found',429:'rate_limited'}.get(exc.code,'http_error')) from None
    except (urllib.error.URLError,TimeoutError,OSError):
        raise ProviderError('network_error') from None
    except (ValueError,UnicodeError):
        raise ProviderError('invalid_json') from None

class VirusTotal:
    name='virustotal'
    def __init__(self,key,transport=get_json): self.key,self.transport=key,transport
    def lookup(self,kind,value):
        paths={'ip':'ip_addresses','domain':'domains','sha256':'files'}
        body=self.transport('https://www.virustotal.com/api/v3/'+paths[kind]+'/'+urllib.parse.quote(value,safe=''),{'x-apikey':self.key})
        try:
            stats=body['data']['attributes']['last_analysis_stats']
            if not isinstance(stats,dict) or not stats or any(type(v) is not int or v<0 for v in stats.values()): raise ValueError
            return {'analysis_stats':stats}
        except (KeyError,TypeError,ValueError): raise ProviderError('invalid_schema') from None

class AbuseIPDB:
    name='abuseipdb'
    def __init__(self,key,transport=get_json): self.key,self.transport=key,transport
    def lookup(self,kind,value):
        if kind!='ip': return {'status':'unsupported_type'}
        query=urllib.parse.urlencode({'ipAddress':value,'maxAgeInDays':90})
        body=self.transport('https://api.abuseipdb.com/api/v2/check?'+query,{'Key':self.key,'Accept':'application/json'})
        try:
            data=body['data']; score,count=data['abuseConfidenceScore'],data['totalReports']
            if type(score) is not int or not 0<=score<=100 or type(count) is not int or count<0: raise ValueError
            return {'abuse_confidence_score':score,'total_reports':count,'window_days':90}
        except (KeyError,TypeError,ValueError): raise ProviderError('invalid_schema') from None

def permitted_live(kind,value):
    if kind=='ip':
        ip=ipaddress.ip_address(value)
        return ip.is_global and not ip.is_multicast
    if kind=='domain':
        return not any(value==x or value.endswith('.'+x) for x in ('test','invalid','localhost','example','example.com','example.net','example.org','local','internal','onion'))
    return True

def run(values,providers=(),fixtures=None,now=None):
    if not 1<=len(values)<=100: raise ValueError('expected 1..100 indicators')
    normalized=[normalize(v) for v in values]
    rows=[]
    for kind,value in dict.fromkeys(normalized):
        results=[]
        if fixtures is not None:
            results=fixtures.get(kind+':'+value,[{'provider':'fixture','status':'no_fixture'}])
        elif not permitted_live(kind,value):
            results=[{'provider':'policy','status':'blocked_nonpublic_or_reserved'}]
        else:
            for provider in providers:
                try: result={'provider':provider.name,'status':'ok',**provider.lookup(kind,value)}
                except ProviderError as exc: result={'provider':provider.name,'status':str(exc)}
                results.append(result)
        rows.append({'type':kind,'indicator':value,'results':results})
    return {'schema_version':1,'mode':'synthetic_offline' if fixtures is not None else 'live',
            'queried_at':now or datetime.now(timezone.utc).isoformat(),'indicators':rows,
            'interpretation':'Observations are not verdicts; no automatic blocking.'}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('input',type=Path)
    p.add_argument('--live',action='store_true')
    p.add_argument('--allow-external-disclosure',action='store_true')
    p.add_argument('--provider',choices=['virustotal','abuseipdb','both'],default='both')
    a=p.parse_args()
    try:
        if a.input.stat().st_size>65536: raise ValueError('input exceeds 64 KiB')
        values=[s.strip() for s in a.input.read_text(encoding='utf-8').splitlines() if s.strip() and not s.lstrip().startswith('#')]
        if a.live:
            if not a.allow_external_disclosure: raise ValueError('live requires --allow-external-disclosure')
            providers=[]
            for cls,env in ((VirusTotal,'VT_API_KEY'),(AbuseIPDB,'ABUSEIPDB_API_KEY')):
                if a.provider in ('both',cls.name):
                    key=os.environ.get(env)
                    if not key: raise ValueError('missing '+env)
                    providers.append(cls(key))
            result=run(values,providers)
        else:
            fixtures=json.loads((Path(__file__).parent/'examples/fixtures.json').read_text())
            result=run(values,fixtures=fixtures)
        print(json.dumps(result,ensure_ascii=False,indent=2))
        failures={'unauthorized','forbidden','rate_limited','http_error','network_error','invalid_json','invalid_schema','response_too_large'}
        return int(any(x['status'] in failures for row in result['indicators'] for x in row['results']))
    except (ValueError,OSError) as exc: p.error(str(exc))

if __name__=='__main__': raise SystemExit(main())
