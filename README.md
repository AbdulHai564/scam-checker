# Scam Checker

A small browser app for spotting common warning signs in messages and website addresses.

[Open Scam Checker](https://abdulhai564.github.io/scam-checker/)

## Run it

Open `index.html` in a browser. Paste a message or select **Website link** and paste an address. Select the check button to see the result and the reasons behind it.

The browser app runs offline when opened from the downloaded project folder. It checks pasted text and URL structure locally. It never opens the submitted address or looks up its reputation. Treat the result as a first pass and verify the source before taking action.

## Code

- `detector.cpp` contains the C++20 detection engine. `MessageDetector` applies the message rules, `WebsiteDetector` evaluates website warning signs, and `RiskAssessment` encapsulates the evidence and calculates the risk level.
- `engine-client.js` uses the browser URL parser to canonicalize addresses and sends the hostname and URL attributes to the C++ engine. For links in messages, it passes the website detector's findings to the message detector.
- `index.html`, `styles.css`, and `app.js` implement the frontend and display the C++ engine's results.
- `scam-engine.js` is the generated browser module with the compiled WebAssembly embedded in it.

## Rebuild the C++ engine

Install and activate the [Emscripten SDK](https://emscripten.org/docs/getting_started/downloads.html). The included browser module was built with Emscripten 4.0.12. With `em++` on your PATH, run this from the project folder after editing the C++ source.

```sh
em++ detector.cpp -std=c++20 -O2 --no-entry -sSINGLE_FILE=1 -sMODULARIZE=1 -sEXPORT_NAME=createScamEngine "-sEXPORTED_FUNCTIONS=_check_website,_check_message,_warning_reason" -sEXPORTED_RUNTIME_METHODS=ccall -o scam-engine.js
```

Commit the rebuilt `scam-engine.js` alongside the C++ changes so GitHub Pages can serve the updated detector.

## Sample inputs

| Input | Expected result |
| --- | --- |
| `See you at lunch tomorrow.` | No common warning signs found |
| `Urgent! Your account will be suspended. Send us your verification code to keep access.` | Strong scam warning signs |
| `example.com` | No common warning signs found |
| `http://example.com` | Use caution |
| `https://example.com@another.example/` | Strong scam warning signs |
