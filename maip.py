import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json
import re
from collections import Counter


def normalize_list_fields(val):
    if isinstance(val, list):
        return ' | '.join(str(v) for v in val)
    return val


def get_win_suspicious_desc(row):
    eid = row.get('EventCode')
    if eid in win_suspicious_eids:
        base = win_suspicious_eids[eid]
        if eid == '4688':
            npn = row.get('New_Process_Name', 'unknown')
            return f"Win: {base} - {npn}"
        elif eid == '4703':
            pn = row.get('Process_Name', 'unknown')
            return f"Win: {base} - {pn}"
        elif eid == '4624':
            lt = row.get('Logon_Type', '?')
            sna = row.get('Source_Network_Address', 'unknown')
            return f"Win: {base} (Type {lt} from {sna})"
        elif eid == '4625':
            lt2 = row.get('Logon_Type', '?')
            sna2 = row.get('Source_Network_Address', 'unknown')
            return f"Win: {base} - {lt2} - {sna2}"
        elif eid == '4672':
            an = row.get('Account_Name', 'unknown')
            return f"Win: {base} - {an}"
        else:
            return f"Win: {base}"
    return None


def is_suspicious_dns(query):
    if not query or not isinstance(query, str):
        return False

    if len(query) > 20:
        return True

    if query.count('.') >= 5:
        return True

    suspicious_tlds = {'.xyz',
                       '.top',
                       '.site',
                       '.club',
                       '.online',
                       '.icu',
                       '.win',
                       '.biz',
                       '.info'}
    if any(tld in query.lower() for tld in suspicious_tlds):
        return True

    subdomain = query.split('.')[0]
    if len(subdomain) >= 8:
        alphanum_ratio = sum(c.isalnum() for c in subdomain) / len(subdomain)
        if alphanum_ratio > 0.8 and not re.search(r'[a-zA-Z]{4,}', subdomain):
            return True

    if re.match(r'^\d+\.\d+\.\d+\.\d+\.in-addr\.arpa$', query.lower()):
        return True

    if query.count('.') < 1:
        return True

    return False


def get_dns_suspicious_desc(row):
    query = row.get('query', '')
    if is_suspicious_dns(query):
        return f"DNS: Suspicious query - {query}"
    return None


try:
    with open('botsv1.json', 'r') as f:
        data = json.load(f)
except FileNotFoundError:
    raise FileNotFoundError("Файл botsv1.json не найден!")

df_raw = pd.DataFrame([rec['result'] for rec in data])
df_norm = df_raw.map(normalize_list_fields)

win_suspicious_eids = {
    '4624': 'Successful Logon',
    '4625': 'Failed Logon',
    '4634': 'Logoff',
    '4648': 'Logon with explicit credentials',
    '4672': 'Special privileges assigned',
    '4688': 'Process Creation',
    '4703': 'Privilege Adjustment',
    '4720': 'User account created',
    '4732': 'Member added to security-enabled group',
    '4738': 'User account changed',
    '4740': 'User account locked out',
    '4768': 'Kerberos TGT requested',
    '4769': 'Kerberos service ticket requested',
    '4776': 'Credential validation',
    '4656': 'Object access requested',
}

df_win = df_norm[df_norm.get(
    'sourcetype',
    '').str.contains(
          'WinEventLog',
          na=False)].copy()
df_win['suspicious_desc'] = df_win.apply(get_win_suspicious_desc, axis=1)
df_win_susp = df_win.dropna(subset=['suspicious_desc'])
df_dns = df_norm[df_norm.get('sourcetype', '').str.contains('DNS', na=False)].copy()

if not df_dns.empty:
    query_counts = Counter(df_dns['query'].dropna())
    threshold = max(query_counts.values()) * 0.05
    frequent_queries = {q for q, cnt in query_counts.items() if cnt > threshold}

    def get_dns_desc_with_freq(row):
        query = row.get('query', '')
        if query in frequent_queries:
            return f"DNS: Frequent query - {query}"
        return get_dns_suspicious_desc(row)

    df_dns['suspicious_desc'] = df_dns.apply(get_dns_desc_with_freq, axis=1)
    df_dns_susp = df_dns.dropna(subset=['suspicious_desc'])
else:
    df_dns_susp = pd.DataFrame(columns=['suspicious_desc'])
    print("DNS-логи не найдены в файле.")

df_all_susp = pd.concat([
    df_win_susp[['suspicious_desc']],
    df_dns_susp[['suspicious_desc']]
], ignore_index=True)

top = df_all_susp['suspicious_desc'].value_counts().head(10).reset_index()
top.columns = ['event_description', 'count']

plt.figure(figsize=(12, 6))
sns.barplot(data=top, y='event_description', x='count', palette='viridis')
plt.xlabel('Количество событий')
plt.title('Топ‑10 подозрительных событий (WinEventLog + DNS)')
plt.tight_layout()
plt.savefig('top_suspicious_combined.png', dpi=100)
plt.show()
