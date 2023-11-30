# data_retrieval.py
import requests
import datetime
from typing import Optional
import bs4

def get_patch_tuesday_data_soup(month: datetime.date, api_url: str, default_ua: str) -> Optional[bs4.BeautifulSoup]:
    url = f"{api_url}/{month.strftime('%Y-%b')}"
    h = requests.get(url, headers={"User-Agent": default_ua})
    if h.status_code != requests.codes.ok:
        raise RuntimeError(f"Unexpected code HTTP/{h.status_code}")
    return bs4.BeautifulSoup(h.text, features="xml")