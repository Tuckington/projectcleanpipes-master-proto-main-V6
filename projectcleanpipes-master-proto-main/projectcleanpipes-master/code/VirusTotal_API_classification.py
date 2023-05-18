import requests
import base64
import csv

def encode_url(url):
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return encoded_url

def retrieve_category(url):
    api_key = "YOUR_API_KEY_HERE"  # Replace with your Virus Total API key
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url}"
    headers = {
        "x-apikey": api_key
    }
    response = requests.get(endpoint, headers=headers)
    if response.status_code == 200:
        data = response.json()
        category = data["data"]["attributes"]["categories"]
        return category
    else:
        return None

# Read malicious URLs from .txt file
input_file = "our_data\malicious_sites.txt"

with open(input_file, "r") as file:
    urls = file.read().splitlines()

# Outputs categories in a .csv file
output_file = "our_results\VirusTotal_website_categories_malicious.csv"

with open(output_file, "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["URL", "Category"])

    for url in urls:
        encoded_url = encode_url(url)
        category = retrieve_category(encoded_url)
        if category is not None:
            writer.writerow([url, category])
        else:
            writer.writerow([url, "Not found"])