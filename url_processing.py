# Program for different functions to be performed on the URL

import numpy as np
import pandas as pd
import requests
from urllib.parse import urlparse
import random
import time

"""
Shannon Entropy
Given by E = -ΣPi * log2(Pi)
where Pi = probability of each character in the URL or domain
"""
def compute_shannon_entropy(url_or_domain):
    if len(url_or_domain) == 0:
        return 0
    char_prob = [float(url_or_domain.count(char))/len(url_or_domain)
                 for char in set(url_or_domain)]
    return -sum([prob * np.log2(prob) for prob in char_prob if prob>0])

def check_for_repeated_digits(url_or_domain_or_sub):
    for char in url_or_domain_or_sub:
        if char.isdigit():
            if url_or_domain_or_sub.count(char) > 1:
                return 1
    return 0

def feature_extractor(url):
    list_features = []

    try:
        parsed = urlparse(url)
        netloc = parsed.netloc
        path = parsed.path
        query = parsed.query
        fragment = parsed.fragment

        features = {
            'url_length': len(url),
            'number_of_dots_in_url': url.count('.'),
            'having_repeated_digits_in_url': check_for_repeated_digits(url),
            'number_of_digits_in_url': sum(char.isdigit() for char in url),
            'number_of_special_char_in_url': sum(not char.isalnum() and char.isascii() for char in url),
            'number_of_hyphens_in_url': url.count('-'),
            'number_of_underline_in_url': url.count('_'),
            'number_of_slash_in_url': url.count('/'),
            'number_of_questionmark_in_url': url.count('?'),
            'number_of_equal_in_url': url.count('='),
            'number_of_at_in_url': url.count('@'),
            'number_of_dollar_in_url': url.count('$'),
            'number_of_exclamation_in_url': url.count('!'),
            'number_of_hashtag_in_url': url.count('#'),
            'number_of_percent_in_url': url.count('%'),

            'domain_length': len(netloc),
            'number_of_dots_in_domain': netloc.count('.'),
            'number_of_hyphens_in_domain': netloc.count('-'),
            'having_special_characters_in_domain': any(not char.isalnum() and char.isascii() for char in netloc),
            'number_of_special_characters_in_domain': sum(not char.isalnum() and char.isascii() for char in netloc),
            'having_digits_in_domain': any(char.isdigit() for char in netloc),
            'number_of_digits_in_domain': sum(char.isdigit() for char in netloc),
            'having_repeated_digits_in_domain': check_for_repeated_digits(netloc),

            'number_of_subdomains': netloc.count('.') - 1 if netloc.count('.') > 1 else 0,
            'having_dot_in_subdomain': netloc.count('.') > 1,
            'having_hyphen_in_subdomain': netloc.count('-') > 0,
            'average_subdomain_length': np.mean([len(subdomain) for subdomain in netloc.split('.')]) if netloc else 0,
            'average_number_of_dots_in_subdomain': np.mean([subdomain.count('.') for subdomain in netloc.split('.')]) if netloc else 0,
            'average_number_of_hyphens_in_subdomain': np.mean([subdomain.count('-') for subdomain in netloc.split('.')]) if netloc else 0,
            'having_special_characters_in_subdomain': any(any(not char.isalnum() and char.isascii() for char in subdomain) for subdomain in netloc.split('.')),
            'number_of_special_characters_in_subdomain': sum(sum(not char.isalnum() and char.isascii() for char in subdomain) for subdomain in netloc.split('.')),
            'having_digits_in_subdomain': any(any(char.isdigit() for char in subdomain) for subdomain in netloc.split('.')),
            'number_of_digits_in_subdomain': sum(sum(char.isdigit() for char in subdomain) for subdomain in netloc.split('.')),
            'having_repeated_digits_in_subdomain': any(check_for_repeated_digits(subdomain) for subdomain in netloc.split('.')),

            'having_path': len(path) > 0,
            'path_length': len(path),
            'having_query': len(query) > 0,
            'having_fragment': len(fragment) > 0,
            'having_anchor': url.count('#') > 0,
            'entropy_of_url': compute_shannon_entropy(url),
            'entropy_of_domain': compute_shannon_entropy(netloc)
        }

        for key, value in features.items():
            list_features.append(value)

        features_df = pd.DataFrame([list_features], columns=features.keys())
        return features_df

    except Exception as e:
        print(f"Error processing URL {url}: {str(e)}")
        return None

def url_fetcher():
    """Fetch URLs from multiple sources for real-time detection"""
    sources = [
        {
            'url': 'https://openphish.com/feed.txt',
            'headers': {'User-Agent': 'Mozilla/5.0'}
        },
        {
            'url': 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-NEW-today.txt',
            'headers': {'User-Agent': 'Mozilla/5.0'}
        },
        {
            'url': 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt',
            'headers': {'User-Agent': 'Mozilla/5.0'}
        },
        {
            'url': 'https://urlhaus.abuse.ch/downloads/text_online/',
            'headers': {'User-Agent': 'Mozilla/5.0'}
        }
    ]

    fetched_urls = set()  # To avoid duplicates
    
    for source in sources:
        try:
            response = requests.get(source['url'], headers=source['headers'], timeout=10)
            if response.status_code == 200:
                urls = response.text.splitlines()
                # Filter out empty lines and add to our set
                fetched_urls.update(filter(None, urls))
                print(f"Fetched {len(urls)} URLs from {source['url']}")
            else:
                print(f"Failed to fetch from {source['url']}, status code: {response.status_code}")
        except Exception as e:
            print(f"Error fetching from {source['url']}: {str(e)}")
    
    # If we couldn't fetch from any source, use a fallback list
    if not fetched_urls:
        print("Using fallback URLs")
        fetched_urls = get_fallback_urls()
    
    return list(fetched_urls)[:100]  # Return first 100 URLs to avoid too many requests

def get_fallback_urls():
    """Return a list of fallback URLs if all sources fail"""
    return [
        "http://paypal.com-security-alert.com",
        "http://facebook-login.secure-account.net",
        "http://appleid.apple.com.verify.account.secure.com",
        "http://netflix-signin.com",
        "http://microsoft-online-security-alert.com",
        "http://whatsapp-web-login.com",
        "http://instagram-account-recovery.com",
        "http://linkedin-security-alert.com",
        "http://twitter-account-verify.com",
        "http://amazon-account-security.com",
        "http://ebay-secure-login.com",
        "http://dropbox-file-share.com",
        "http://google-drive-security-alert.com",
        "http://yahoo-mail-account-recovery.com",
        "http://outlook-account-verify.com",
        "http://bankofamerica-secure-login.com",
        "http://wellsfargo-online-banking.com",
        "http://chase-secure-login.com",
        "http://citibank-online-security.com",
        "http://usbank-secure-login.com"
    ]