import requests

response = requests.post("https://api.featherless.ai/v1/chat/completions", headers = {"Authorization": "Bearer rc_195aa500d7780f00f8e6a1c161d45193d73a201a9c40f1a597b23c3f171591cb"}, 
            json={
                "model" : "moonshotai/Kimi-K2.5",
                "messages" : [
                    {"role":"user","content":"How are you doing today?"}
                ]
            }
        )
print(response.json()["choices"][0]["message"]["content"])