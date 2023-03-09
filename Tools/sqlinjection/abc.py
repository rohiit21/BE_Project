crawled_urls = [    "https://www.example.com/index.html",    "https://www.example.com/about?id=1",    "https://www.example.com/contact"]

filtered_urls = []

for url in crawled_urls:
    if "?" in url:
        filtered_urls.append(url)

print(filtered_urls)
