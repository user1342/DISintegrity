<p align="center">
    <img width=100% src="coverimage.gif">
  </a>
</p>
<b><p align="center"> 🤖 A tool for analysing Android APKs and extracting root, integrity, and tamper detection checks 📱 </p></b>

<br>
<div align="center">

![GitHub contributors](https://img.shields.io/github/contributors/user1342/DISintegrity)
![GitHub Repo stars](https://img.shields.io/github/stars/user1342/DISintegrity?style=social)
![GitHub watchers](https://img.shields.io/github/watchers/user1342/DISintegrity?style=social)
![GitHub last commit](https://img.shields.io/github/last-commit/user1342/DISintegrity)

</div>

DISintegrity is a tool for analyzing Android APKs, focusing on identifying root, integrity, and tamper detection checks inside of the APK. It uses APKTool to break down APK files and extracts data from Android manifests, smali code, and other resources to identify these security checks. The tool generates an easy-to-understand HTML report, helping offensive security researchers identify root and tamper detection checks in APKs for ptaching, hooking, and mitigating.

# ➡️ Getting Started
## Installation
Getting started with DIS{integrity} is easy! Follow these steps:

1) Clone the repository to your local machine.
2) Install the dependencies manually or via the included requirements file using the following command:
```bash
pip install -r REQUIREMENTS.txt
```
3) **Download APKTool for your system from [their website](https://ibotpeaches.github.io/Apktool/documentation/). and make sure it's installed and available in your PATH.**

DIS{integrity} has been tested on Windows 11.

## Running
DIS{integrity} takes the following arguments. ```-apk``` is required. 

```
Detect root checks in Android APK files

arguments:
  -h, --help            show this help message and exit
  -apk APK_FILE_PATH, --apk_file_path APK_FILE_PATH the path to the APK file to analyze
  -o OUTPUT_DIR, --output-dir OUTPUT_DIR the output directory to store the analysis results
  --apktool APKTOOL     the path to the apktool executable if not on PATH
```

Then run DIS{integrity} as follows. Afterwhich a HTML output file will be created.

```
python DISintegrity.py -apk <path to apk>
```

<p align="center">
  <img src="demo.gif" width="800" />
</p>

# 🙏 Contributions
DIS{integrity} is an open-source project and welcomes contributions from the community. If you would like to contribute to DIS{integrity}, please follow these guidelines:

- Fork the repository to your own GitHub account.
- Create a new branch with a descriptive name for your contribution.
- Make your changes and test them thoroughly.
- Submit a pull request to the main repository, including a detailed description of your changes and any relevant documentation.
- Wait for feedback from the maintainers and address any comments or suggestions (if any).
- Once your changes have been reviewed and approved, they will be merged into the main repository.

# ⚖️ Code of Conduct
DIS{integrity} follows the Contributor Covenant Code of Conduct. Please make sure [to review](https://www.contributor-covenant.org/version/2/1/code_of_conduct/code_of_conduct.md). and adhere to this code of conduct when contributing to DIS{integrity}.

# 🐛 Bug Reports and Feature Requests
If you encounter a bug or have a suggestion for a new feature, please open an issue in the GitHub repository. Please provide as much detail as possible, including steps to reproduce the issue or a clear description of the proposed feature. Your feedback is valuable and will help improve DIS{integrity} for everyone.

# 💛 Thanks
This tool wouldn't work without [APKTool](https://ibotpeaches.github.io/Apktool/documentation/)! 

# 📜 License
[GNU General Public License v3.0](https://choosealicense.com/licenses/gpl-3.0/)
