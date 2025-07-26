HIBP_API_URL="https://haveibeenpwned.com/api/v3/breachedaccount/"
IP_API_URL="https://ipapi.co/{}/json/"

HEADERS ={
  "USER": "CybrixTools",
}

def get_whois(domain):
  try:
    info=whois.whois(domain)
    return info.text if hasattr(info, 'text') else str(info)
  except Exception as e:
    return f"WHOIS experienced error: {str(e)}"

def get_ip_geoloc(ip):
  try:
    url=IP_API_URL.format(ip)
    res=requests.get(url)
    if res.status_code !=200:
      return f"Geo experienced error: Status {res.status_code}"
    data=res.json()
    return f"{data.get('ip')} - {data.get('city')}, {data.get('region')}, {data.get('country_name')} (ISP: {data.get('org')})"
  except Exception as e:
    return f"Geo experienced error: {str(e)}"

def check_email_breaches(email):
  try:
    url=HIBP_API_URL + email
    res=requests.get(url, headers=HEADERS)
    if res.status_code == 404:
      return "No Breaches Found!"
    elif res.status_code == 200:
      breaches = res.json()
      return f"Breached in: " + ", ".join(b['Name'] for b in breaches)
    elif res.status_code == 429:
      return "Exceeded rate limit, try again later."
    else:
      return f"HIBP experienced an error: {res.status_code}"
except Exception as e:
  return f"HIBP experienced an error: {str(e)}
