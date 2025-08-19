import requests

url = input("Enter website URL to test: ")
response = requests.get(url)
print(f"Website {url} returned status code: {response.status_code}")
