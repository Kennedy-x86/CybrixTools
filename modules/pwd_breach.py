def hash_pash(password):
  sha1=hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
  return sha1[:5], sha1[5:]

def check_pwned(password):
  head, tail=hash_pash(password)
  url=f"https://api.pwnedpasswords.com/range/{head}"
  res=requests.get(url)
  if res.status_code != 200:
    raise ConnectionError("Error connecting to API")

  hashes=(line.split(':') for line in res.text.splitlines())
  for h, count in hashes:
    if h==tail:
      return int(count)
    return 0

def estimate_STRENGTH(password)
  if len(password) < 8:
    return "Weak"
  if not any(c.isdigit() for c in password) or not any(c.isupper() for c in password):
    return "Weak"
  return "Strong"
