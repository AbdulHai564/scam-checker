# Scam Checker

A small browser app for spotting common warning signs in messages and website addresses.

[Open Scam Checker](https://abdulhai564.github.io/scam-checker/)

## Run it

Open `index.html` in a browser. Paste a message or select **Website link** and paste an address. Select the check button to see the result and the reasons behind it.

The browser app runs offline when opened from the downloaded project folder. It checks pasted text and URL structure locally. It never opens the submitted address or looks up its reputation. Treat the result as a first pass and verify the source before taking action.

The website checker flags single-character typos and swapped adjacent letters in lookalikes for Amazon, Google, Microsoft, Netflix, and PayPal.

## Code

- `detector.cpp` contains the C++20 detection engine. `MessageClassifier` scores learned word and phrase patterns, `MessageDetector` combines the classifier with the rules, `WebsiteDetector` evaluates addresses, and `RiskAssessment` calculates the risk level.
- `message_model.h` contains the generated model weights. The classifier can raise a caution. Strong warnings come from the rules and link analysis.
- `engine-client.js` uses the browser URL parser to canonicalize addresses and sends the hostname and URL attributes to the C++ engine. For links in messages, it passes the website detector's findings to the message detector.
- `index.html`, `styles.css`, and `app.js` implement the frontend and display the C++ engine's results.
- `scam-engine.js` is the generated browser module with the compiled WebAssembly embedded in it.

## Rebuild the C++ engine

Install and activate the [Emscripten SDK](https://emscripten.org/docs/getting_started/downloads.html). The included browser module was built with Emscripten 4.0.12. With `em++` on your PATH, run this from the project folder after editing the C++ source.

```sh
em++ detector.cpp -std=c++20 -O2 --no-entry -sSINGLE_FILE=1 -sMODULARIZE=1 -sEXPORT_NAME=createScamEngine "-sEXPORTED_FUNCTIONS=_check_website,_check_message,_warning_reason" -sEXPORTED_RUNTIME_METHODS=ccall -o scam-engine.js
```

Commit the rebuilt `scam-engine.js` alongside the C++ changes so GitHub Pages can serve the updated detector.

## Message model and evaluation

The model is a small logistic regression trained on English SMS wording. It uses individual words and adjacent word pairs. Training replaces URLs and numbers with generic tokens, ignores generic spam labels, and supplements public data with authored examples of legitimate notices. The trainer groups messages by normalized opening before splitting them and chooses the threshold on the validation split.

The combined rules and classifier caught **1,852 of 1,900** labeled scam messages in the held-out split and flagged **27 of 725** labeled legitimate messages. The previous rules caught **293 of 1,900** scams and flagged **12 of 725** legitimate messages on the same split. On the classifier-only SmishX subset, it caught **35 of 35** scam messages and flagged **12 of 91** legitimate messages. These figures describe the test data. Performance can vary for new senders, conversations, languages, and scam types.

To reproduce training, download the Mendeley ZIP and the two CSVs from the sources below and keep them outside the repository. Then run the trainer, rebuild the C++ engine using the command above, and run the smoke tests. The optional holdout file contains raw dataset text and should stay outside the repository.

```sh
python tools/train_message_model.py /path/to/Dataset_5971.zip /path/to/final_dataset_output.csv /path/to/dataset.csv --test-output /path/to/holdout.json
node tools/check_message_model.cjs /path/to/holdout.json
```

- Sandhya Mishra and Devpriya Soni, *SMS Phishing Dataset for Machine Learning and Pattern Recognition* (CC BY 4.0). [Mendeley Data](https://data.mendeley.com/datasets/f45bkkt8pr/1)
- Sharad Agarwal, Antonis Papasavva, Guillermo Suarez-Tangil, and Marie Vasek, *Fishing for Smishing* (CC BY 4.0). [IMC dataset](https://github.com/reportsmishing/Smishing-Dataset-IMC25)
- Yizhu Wang and colleagues, *Can You Walk Me Through It? Explainable SMS-Phishing Detection Using LLM-Based Agents*. [SmishX dataset](https://github.com/yizhu-joy/SmishX/tree/main/data)

## Sample inputs

| Input | Expected result |
| --- | --- |
| `Dinner at seven? I can pick you up on the way.` | Couldn’t determine from this message |
| `Urgent! Your account will be suspended. Send us your verification code to keep access.` | Strong scam warning signs |
| `example.com` | Couldn’t verify this website |
| `http://example.com` | Use caution |
| `https://example.com@another.example/` | Strong scam warning signs |
