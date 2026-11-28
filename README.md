# Scam Checker

Scam Checker is a C++20 web app with a dark HTML and CSS interface. It checks English messages and website addresses for common scam warning signs.

## Run locally

Build with CMake 3.21 or later and a 64-bit C++20 compiler. The first build downloads the pinned C++ dependencies.

**Windows** with Visual Studio or Build Tools and the Desktop development with C++ workload:

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
.\build\Release\scam-checker.exe
```

**Linux or macOS:**

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
./build/scam-checker
```

Open [Scam Checker on this computer](http://127.0.0.1:8080/). Choose **Message** or **Website link**, then submit your own text or select **Check an example** to run a built-in sample immediately.

The server binds to loopback by default. It does not log or store pasted content or open submitted links. When hosted publicly, the HTML forms send submissions to that host’s C++ server over HTTPS. The risk result reflects text and address patterns. Verify the sender or domain before acting.

The website checker shows the parsed hostname and flags common link shorteners, disguised brand domains, encoded hostnames, nonstandard ports, and possible external destinations named in redirect parameters. It evaluates the address text without following redirects or looking up site reputation.

## Host on a web service

The `Dockerfile` builds a Linux image with the frontend embedded. It listens on `0.0.0.0` using the `PORT` environment variable, with `8080` as the container default. Use `/health` for the health check and let the hosting service terminate HTTPS. GitHub Pages serves the static project information page.

## Code

- `detector.cpp` contains the C++ detector classes and assessment logic.
- `message_model.h` contains the existing trained weights used by the offline classifier.
- `server.cpp` handles HTML forms, URL parsing, examples, and response rendering.
- `web/checker.html` and `styles.css` define the interface.

## Message model and evaluation

The model is a small logistic regression trained on English SMS wording. It uses individual words and adjacent word pairs. It can raise a caution. Strong warnings come from the rules and link analysis.

The native C++ server caught **1,852 of 1,900** labeled scam messages in the held-out split and flagged **27 of 725** labeled legitimate messages. These figures describe that test data. Performance can vary for new senders, conversations, languages, and scam types.

- Sandhya Mishra and Devpriya Soni, *SMS Phishing Dataset for Machine Learning and Pattern Recognition* (CC BY 4.0). [Mendeley Data](https://data.mendeley.com/datasets/f45bkkt8pr/1)
- Sharad Agarwal, Antonis Papasavva, Guillermo Suarez-Tangil, and Marie Vasek, *Fishing for Smishing* (CC BY 4.0). [IMC dataset](https://github.com/reportsmishing/Smishing-Dataset-IMC25)
- Yizhu Wang and colleagues, *Can You Walk Me Through It? Explainable SMS-Phishing Detection Using LLM-Based Agents*. [SmishX dataset](https://github.com/yizhu-joy/SmishX/tree/main/data)
