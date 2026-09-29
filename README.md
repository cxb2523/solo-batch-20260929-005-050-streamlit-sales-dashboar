
# Add a User Authentication Service (Login Form) in Streamlit

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


## Local Credential Web App

The bcrypt credential logic from `generate_keys.py` is also served by a local
FastAPI app (`app.py`):

```bash
uvicorn app:app          # http://127.0.0.1:8000
```

- `GET /` renders the credential panel (read-only badge, source, version, algorithm, last rotation time).
- `POST /keys/rotate` reads two passphrases (or ``username:pass`` lines) from stdin, hashes with bcrypt and writes `credentials.json` atomically.
- `POST /keys/verify` reads a single ``username:pass`` line from stdin.
- Invalid source/algorithm/version at startup switches the store to read-only and returns `409` from both endpoints.
- Legacy `hashed_pw.pkl` stays readable; the first write migrates to JSON (with byte-for-byte rollback on failure).
- Source precedence: file > environment variable (`CREDENTIALS_JSON`) > config dir (`~/.config/sales-dashboard`) > legacy pickle. File changes hot-reload within 5 seconds; other sources never trigger reloads.
- Tests: `pytest -q`.
