
# Add a User Authentication Service (Login Form) in Streamlit

## Credential service (uvicorn)

The key-generation logic from `generate_keys.py` now lives in a local ASGI
service. Start it with:

```bash
uvicorn app:app
```

* `GET /` — credential panel (read-only/read-write badge, source, version,
  algorithm, last rotation time)
* `POST /keys/rotate` — rotate one user (`{"usernames": ["pparker"]}`) or all
* `POST /keys/verify` — verify `{"username": "pparker"}`
* `GET /keys/state` — machine-readable status

Credentials are stored in `credentials.json` with `version` and `algorithm`
fields. Behavioural guarantees:

* The legacy `hashed_pw.pkl` stays readable; the first rotation writes JSON and
  retires the pickle. A failure mid-migration restores the original file
  byte-for-byte.
* Source priority is credentials file, then `CREDENTIALS_JSON` env var, then
  the config directory. File edits are hot-reloaded within 5 seconds; env/config
  changes never trigger a reload.
* Passphrases are read from the server process **stdin** only and wiped from
  memory immediately; they are never logged or taken from env vars.
* Writes go through a same-directory temp file + `os.replace`; concurrent
  rotations are serialised with a file lock (`credentials.json.lock`).
* An unsupported algorithm or a newer-than-supported credential version flips
  the service into read-only mode and makes mutating routes return `409`.

In this video, I will show you how to add a user authentication service (login form) in Streamlit so that your users can log in and see the content of your streamlit app. To implement the user authentication, we will use the ‘streamlit-authenticator’ library, a secure authentication module to validate user credentials in a Streamlit application.

## Video Tutorial
[![YouTube Video](https://img.youtube.com/vi/JoFGrSRj4X4/0.jpg)](https://youtu.be/JoFGrSRj4X4)

## Demo Website
⭐ https://userauth-dashboard.herokuapp.com/

## Screenshot
![Login Screenshot](/demo.jpg?raw=true "Login Form")

## Streamlit-authenticator
⭐ Check out the library here: https://github.com/mkhorasani/Streamlit-Authenticator

## Learn Excel Automation with Python
If this repo helped you, my [Excel Automation Course](https://pythonandvba.com/excel-automation-course/) teaches the full workflow from zero: Python for Excel users, xlwings, pandas and real projects.

Also check out my other [tools and templates](https://pythonandvba.com/solutions).

## Connect with Me
- **YouTube:** [CodingIsFun](https://youtube.com/c/CodingIsFun)
- **Website:** [PythonAndVBA](https://pythonandvba.com)
- **LinkedIn:** [Sven Bosau](https://www.linkedin.com/in/sven-bosau/)
- **Contact:** [Get in Touch](https://pythonandvba.com/contact)
## Support
If you find this project helpful, consider buying me a coffee. 

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://pythonandvba.com/coffee-donation)
