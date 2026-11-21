# Scam Checker

A small browser app for spotting common warning signs in messages and website addresses.

## Run it

Open `index.html` in a browser. Paste a message or select **Website link** and paste an address. Select the check button to see the result and the reasons behind it.

No installation, account, or internet connection is required. The app checks pasted text and URL structure locally. It never opens the submitted address or looks up its reputation. Treat the result as a first pass and verify the source before taking action.

## Code

- `index.html` and `styles.css` define the interface.
- `detectors.js` contains the `MessageDetector`, `WebsiteDetector`, and `RiskAssessment` classes. The message detector reuses the website detector for links embedded in messages.
- `app.js` contains `ScamCheckerApp`, which connects both forms to their detectors and displays the results.

## Sample inputs

| Input | Expected result |
| --- | --- |
| `See you at lunch tomorrow.` | No common warning signs found |
| `Urgent! Your account will be suspended. Send us your verification code to keep access.` | Strong scam warning signs |
| `example.com` | No common warning signs found |
| `http://example.com` | Use caution |
| `https://example.com@another.example/` | Strong scam warning signs |
