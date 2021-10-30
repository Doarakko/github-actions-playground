import requests

r = requests.get("https://db.ygoprodeck.com/api/v7/randomcard.php").json()

print("Draw \"{}\"\n{}".format(r["name"], r["card_images"][0]["image_url"]))
